package soroauth

// Version is the library's release tag. The release workflow stamps it at
// build time via:
//
//	-ldflags "-X github.com/soroauth/soroauth-go.Version=v0.x.0"
//
// In a source-tree build it is "dev", which signals plainly that the binary
// was not built by the release workflow. An empty string is never the default:
// an empty version reads as a parsing bug in a bug report, whereas "dev" says
// what actually happened.
var Version = "dev"
