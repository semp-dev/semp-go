// Package h2 implements the SEMP HTTP/2 transport binding. The binding uses
// path-based routing on a single HTTPS base URL:
//
//	POST /v1/discovery     — discovery lookup
//	POST /v1/keys          — key request
//	POST /v1/handshake     — handshake message exchange
//	POST /v1/envelope      — envelope submission
//	POST /v1/session/{id}  — long-lived session stream (server-pushed
//	                          messages via Server-Sent Events)
//
// Request and response bodies are application/json; charset=utf-8.
//
// Specification reference: TRANSPORT.md §4.2.
package h2
