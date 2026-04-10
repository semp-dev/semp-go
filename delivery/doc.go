// Package delivery implements the SEMP delivery pipeline: the fixed
// sequence of checks every envelope passes through before a delivery
// decision is made, the block list with its three entity types and three
// scopes, multi-device block list synchronization via SEMP_BLOCK, recipient
// status visibility (the autoresponder replacement defined in
// DELIVERY.md §1.6), and the internal-route enforcement applied when
// envelopes cross between partition servers within the same domain.
//
// Specification reference: DELIVERY.md.
package delivery
