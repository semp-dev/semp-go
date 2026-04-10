// Command semp-server is the reference SEMP server binary.
//
// In the current skeleton it does nothing useful: it prints a banner and
// exits. The real implementation will wire together the discovery,
// handshake, session, delivery, and transport packages and serve a
// SEMP-only home server over the configured transports.
package main

import (
	"fmt"
	"os"

	semp "github.com/semp-dev/semp-go"
)

func main() {
	fmt.Fprintf(os.Stderr, "semp-server %s — skeleton build, not yet implemented\n", semp.ProtocolVersion)
	fmt.Fprintln(os.Stderr, "See README.md and the per-package TODO markers for the work queue.")
	os.Exit(0)
}
