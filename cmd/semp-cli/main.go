// Command semp-cli is the reference SEMP client CLI.
//
// Planned subcommands:
//
//	semp-cli send     <to> [flags]   compose and send an envelope
//	semp-cli receive  [flags]        retrieve waiting envelopes
//	semp-cli keys     <subcommand>   manage device, identity, and encryption keys
//
// In the current skeleton none of these subcommands are wired up; the
// binary prints a banner and exits.
package main

import (
	"fmt"
	"os"

	semp "github.com/semp-dev/semp-go"
)

func main() {
	fmt.Fprintf(os.Stderr, "semp-cli %s — skeleton build, not yet implemented\n", semp.ProtocolVersion)
	if len(os.Args) > 1 {
		fmt.Fprintf(os.Stderr, "subcommand %q is not yet supported\n", os.Args[1])
	}
	fmt.Fprintln(os.Stderr, "See README.md and the per-package TODO markers for the work queue.")
	os.Exit(0)
}
