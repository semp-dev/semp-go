// Package ws implements the SEMP WebSocket transport binding.
//
// Connection establishment uses HTTPS-style URLs (wss://) and the
// "semp.v1" subprotocol identifier in the HTTP Upgrade request. Each SEMP
// message is sent as a single WebSocket text frame containing the UTF-8
// JSON message; binary frames MUST NOT be used (TRANSPORT.md §4.1.2).
//
// Implementations of this binding will use a third-party WebSocket library
// (the planned dependency is github.com/coder/websocket) once the skeleton
// transitions to a real implementation. The skeleton uses only stdlib
// types so that the package can be referenced from cmd binaries today.
//
// Specification reference: TRANSPORT.md §4.1.
package ws
