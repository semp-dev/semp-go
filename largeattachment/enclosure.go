package largeattachment

import (
	"encoding/json"
	"errors"
	"fmt"

	"semp.dev/semp-go/extensions"
)

// ReadFromExtensions returns the slice of Items carried in the
// `semp.dev/large-attachment` entry of m. Returns (nil, nil) when
// the extension is absent. Returns an error when the entry exists
// but cannot be decoded into ExtensionData.
//
// The function tolerates either a structured ExtensionData shape
// (the canonical form produced by AppendToExtensions) or the wire-
// level json.RawMessage form callers receive after decoding an
// envelope.
func ReadFromExtensions(m extensions.Map) ([]Item, error) {
	if m == nil {
		return nil, nil
	}
	entry, ok := m[ExtensionKey]
	if !ok {
		return nil, nil
	}
	switch v := entry.Data.(type) {
	case nil:
		return nil, nil
	case ExtensionData:
		out := make([]Item, len(v.Items))
		copy(out, v.Items)
		return out, nil
	case *ExtensionData:
		if v == nil {
			return nil, nil
		}
		out := make([]Item, len(v.Items))
		copy(out, v.Items)
		return out, nil
	}
	// Generic decode: marshal then unmarshal into ExtensionData.
	raw, err := json.Marshal(entry.Data)
	if err != nil {
		return nil, fmt.Errorf("largeattachment: marshal extension entry: %w", err)
	}
	var data ExtensionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("largeattachment: parse extension data: %w", err)
	}
	return data.Items, nil
}

// AppendToExtensions inserts items into the
// `semp.dev/large-attachment` entry of m, creating the entry when
// absent and merging when present. The merge preserves any existing
// items already in the entry; new item ids that collide with an
// existing id return an error rather than silently overwriting.
//
// AppendToExtensions does not enforce extension-size limits; the
// caller's envelope-encoder still calls extensions.ValidateSize
// against the layer's bound per ENVELOPE.md §4.2.
//
// The entry's `required` flag is left as the caller set it;
// `semp.dev/large-attachment` is OPTIONAL by spec, but operators
// may flip required for their own deployment policy.
func AppendToExtensions(m extensions.Map, items ...Item) (extensions.Map, error) {
	if m == nil {
		m = make(extensions.Map)
	}
	if len(items) == 0 {
		return m, nil
	}
	for i, it := range items {
		if err := it.Validate(); err != nil {
			return m, fmt.Errorf("largeattachment: items[%d]: %w", i, err)
		}
	}

	existing, err := ReadFromExtensions(m)
	if err != nil {
		return m, err
	}
	seen := make(map[string]struct{}, len(existing)+len(items))
	merged := make([]Item, 0, len(existing)+len(items))
	for _, it := range existing {
		merged = append(merged, it)
		seen[it.ID] = struct{}{}
	}
	for _, it := range items {
		if _, dup := seen[it.ID]; dup {
			return m, fmt.Errorf("largeattachment: duplicate id %q in extension entry", it.ID)
		}
		merged = append(merged, it)
		seen[it.ID] = struct{}{}
	}

	prior := m[ExtensionKey]
	m[ExtensionKey] = extensions.Entry{
		Required: prior.Required,
		Data:     ExtensionData{Items: merged},
	}
	return m, nil
}

// SetOnExtensions replaces the `semp.dev/large-attachment` entry's
// items with items, discarding any prior items. Use this when the
// caller is composing the entry from scratch (typical sender
// flow: build the full attachment list, then set it once).
//
// The required flag and any other extension keys are preserved.
func SetOnExtensions(m extensions.Map, items ...Item) (extensions.Map, error) {
	if m == nil {
		m = make(extensions.Map)
	}
	for i, it := range items {
		if err := it.Validate(); err != nil {
			return m, fmt.Errorf("largeattachment: items[%d]: %w", i, err)
		}
	}
	prior := m[ExtensionKey]
	m[ExtensionKey] = extensions.Entry{
		Required: prior.Required,
		Data:     ExtensionData{Items: append([]Item(nil), items...)},
	}
	return m, nil
}

// RemoveFromExtensions drops the `semp.dev/large-attachment` entry
// from m. No-op when the entry is absent. Returns m for chaining.
func RemoveFromExtensions(m extensions.Map) extensions.Map {
	if m == nil {
		return m
	}
	delete(m, ExtensionKey)
	return m
}

// FindByID returns the item with the given id from the
// `semp.dev/large-attachment` entry of m. Returns (Item{}, false)
// when no match exists. The "found" flag distinguishes a missing
// id from a present id whose Item is the zero value.
func FindByID(m extensions.Map, id string) (Item, bool) {
	items, err := ReadFromExtensions(m)
	if err != nil {
		return Item{}, false
	}
	for _, it := range items {
		if it.ID == id {
			return it, true
		}
	}
	return Item{}, false
}

// errors collected here so callers can branch via errors.Is.
var (
	// ErrExtensionMissing is returned when a caller asks for the
	// extension entry on a Map that does not carry it. Currently
	// used only by FindByID-style callers that want to distinguish
	// "not present" from "present but empty"; ReadFromExtensions
	// itself returns (nil, nil) for the missing case.
	ErrExtensionMissing = errors.New("largeattachment: extension entry not present")
)
