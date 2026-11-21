"""Install the wheel at --wheel and replay every golden vector through it.

The release workflow runs this in a clean environment — a venv with only
pip — to catch two classes of regression in one job:

  1. The wheel does not install (missing native library, missing marker,
     a package-data stanza that excluded something).
  2. The installed wheel installs cleanly but gives different bytes than
     the Go library. This is what makes the publish job ever OK.

Byte equality against the committed vectors is the only pass condition.
Exceptions bubble up.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any


def install_wheel(wheel: pathlib.Path) -> None:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--force-reinstall", str(wheel)]
    )


def install_runtime_deps() -> None:
    # The wheel declares cffi; a clean venv has no cffi yet.
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cffi>=1.15.0"])


def load_vectors(vectors_dir: pathlib.Path) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for path in sorted(vectors_dir.glob("*.json")):
        with path.open(encoding="utf-8") as fh:
            out.append((path.name, json.load(fh)))
    if not out:
        raise SystemExit(f"no vectors in {vectors_dir}")
    return out


def replay(vectors: list[tuple[str, dict[str, Any]]]) -> None:
    # Import late so the import happens against the installed wheel, not
    # a dev checkout on sys.path.
    import soroauth  # type: ignore[import-not-found]

    ver = soroauth.version()
    print(f"loaded soroauth ABI {ver}")

    ran_preimage = 0
    ran_authorize = 0
    for name, v in vectors:
        if not v.get("preimage_xdr"):
            # Source-account vectors have no preimage path; just prove
            # inspect returns the right shape for them.
            info = soroauth.inspect(v["unsigned_entry_xdr"])
            if info.get("credential_type") != "source_account":
                raise SystemExit(
                    f"{name}: inspect credential_type was {info.get('credential_type')!r}"
                )
            continue

        pre = soroauth.preimage(
            v["unsigned_entry_xdr"], v["valid_until_ledger"], v["network_passphrase"]
        )
        if pre.preimage_xdr != v["preimage_xdr"]:
            raise SystemExit(f"{name}: preimage drift")
        if pre.payload_hex != v["payload_hex"]:
            raise SystemExit(f"{name}: payload drift")
        ran_preimage += 1

        steps = v.get("steps") or []
        has_multisig = any(s.get("multisig") for s in steps)
        if (
            not v.get("signed_entry_xdr")
            or len(steps) != 1
            or has_multisig
        ):
            # Single-step single-key replay is what the C ABI call
            # authorize_with_seed exposes; multi-step and multisig vectors
            # are proved by the Go suite and cover a different path.
            continue

        step = steps[0]
        seed = hashlib.sha256(step["signer_label"].encode()).digest().hex()
        signed = soroauth.authorize_with_seed(
            v["unsigned_entry_xdr"],
            v["valid_until_ledger"],
            v["network_passphrase"],
            seed,
            step.get("for_address"),
        )
        if signed.entry_b64 != v["signed_entry_xdr"]:
            raise SystemExit(f"{name}: signed entry drift")
        ran_authorize += 1

    print(f"preimage/payload byte-equal: {ran_preimage}")
    print(f"authorize_with_seed byte-equal: {ran_authorize}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wheel", type=pathlib.Path, help="wheel to install (optional)")
    ap.add_argument(
        "--vectors",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors",
    )
    args = ap.parse_args()

    install_runtime_deps()
    if args.wheel is not None:
        install_wheel(args.wheel)

    vectors = load_vectors(args.vectors)
    replay(vectors)
    print("smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
