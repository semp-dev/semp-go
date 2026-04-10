// Package extensions implements the SEMP extension framework: the structure
// of extension entries, criticality signaling via the `required` flag, the
// per-layer size limits enforced by routing servers, namespace validation,
// and the lifecycle states a registered extension may occupy.
//
// Every layer of an envelope (postmark, seal, brief, enclosure) carries an
// `extensions` object whose entries are key-value pairs governed by this
// package. Handshake messages, discovery responses, and block list entries
// have analogous extension points with the same shape.
//
// Specification reference: EXTENSIONS.md.
package extensions
