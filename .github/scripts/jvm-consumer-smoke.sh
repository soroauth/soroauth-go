#!/usr/bin/env bash
# Build a consumer Maven project against `org.soroauth:soroauth-jvm:<version>`
# as resolved from Maven Central, and replay every golden vector through it.
#
# This is what makes the "clean-container consumer test resolves the
# published artifact and replays the golden vectors" acceptance line from
# issue #544 bite: the project it builds has no local path to the binding's
# source tree, so a wheel that resolves but whose bytes disagree with the
# vectors fails here.
set -euo pipefail

if [ "${#}" -lt 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi
version="$1"

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src/main/java/soroauth_consumer"
cat >"$work/pom.xml" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>consumer</groupId>
  <artifactId>soroauth-jvm-consumer</artifactId>
  <version>0.0.0</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.release>22</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.soroauth</groupId>
      <artifactId>soroauth-jvm</artifactId>
      <version>${version}</version>
    </dependency>
  </dependencies>
</project>
POM

# A minimal consumer: loads the native library through the published jar's
# own NativeLoader and replays the first vector's payload. The point is
# resolution + a live call, not the full golden suite — the binding's
# own `mvn test` is the full suite, and this job only needs to catch
# "the published artifact does not install or does not run".
cat >"$work/src/main/java/soroauth_consumer/Smoke.java" <<'JAVA'
package soroauth_consumer;

import java.nio.file.*;
import java.util.*;
import org.soroauth.Soroauth;

// A minimal consumer: for every vector that has a preimage_xdr, assert
// that the published Soroauth.payloadHex of that preimage equals the
// vector's recorded payload_hex. Resolution + the native library load
// + one live call across the FFM boundary — that's what this smoke
// proves. The binding's own `mvn test` covers the whole suite; this
// job only needs to catch "the published artifact does not install or
// does not run".
public final class Smoke {
    public static void main(String[] args) throws Exception {
        Path vectorsDir = Paths.get(args[0]);
        try (var stream = Files.list(vectorsDir)) {
            var paths = new ArrayList<Path>();
            stream.filter(p -> p.toString().endsWith(".json")).forEach(paths::add);
            Collections.sort(paths);
            if (paths.isEmpty()) {
                throw new IllegalStateException("no vectors in " + vectorsDir);
            }
            int exercised = 0;
            for (Path p : paths) {
                var text = Files.readString(p);
                var preimageXdr = extract(text, "preimage_xdr");
                var payloadHex = extract(text, "payload_hex");
                if (preimageXdr == null || preimageXdr.isEmpty()) {
                    // Source-account vectors have no preimage path.
                    continue;
                }
                var got = Soroauth.payloadHex(preimageXdr);
                if (!got.equals(payloadHex)) {
                    throw new IllegalStateException(
                        "payload drift in " + p.getFileName()
                        + ": got " + got + " want " + payloadHex);
                }
                exercised++;
            }
            System.out.println("consumer-smoke: payload byte-equal across " + exercised + " vectors");
        }
    }

    private static String extract(String json, String key) {
        var needle = "\"" + key + "\"";
        int i = json.indexOf(needle);
        if (i < 0) return null;
        i = json.indexOf(':', i) + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length()) return null;
        if (json.charAt(i) == '"') {
            int end = json.indexOf('"', i + 1);
            return json.substring(i + 1, end);
        }
        int end = i;
        while (end < json.length() && "0123456789-".indexOf(json.charAt(end)) >= 0) end++;
        return json.substring(i, end);
    }
}
JAVA

cd "$work"
mvn -B -q -U compile
mvn -B -q exec:java -Dexec.mainClass=soroauth_consumer.Smoke -Dexec.args="${repo_root}/testdata/vectors"
