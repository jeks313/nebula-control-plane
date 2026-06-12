// Command harbor is the Nebula Control Plane central service (enrollment, IPAM,
// signing, policy, rotation). Stub for now — built out from milestone M2.
package main

import "fmt"

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	fmt.Printf("harbor %s — not yet implemented (see docs/, milestone M2)\n", version)
}
