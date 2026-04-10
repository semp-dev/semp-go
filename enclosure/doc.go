// Package enclosure defines the encrypted message body and attachments
// portion of a SEMP envelope. The enclosure is encrypted under K_enclosure,
// which is wrapped only under the recipient client's encryption key. No
// server (sender's, recipient's, or any intermediary) can read the
// enclosure under any circumstances.
//
// Specification reference: ENVELOPE.md §6.
package enclosure
