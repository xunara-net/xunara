package state

// DeviceAttrStore stores the device posture attributes a node reports about
// itself through /machine/set-device-attr (tailcfg.AttrUpdate).
//
// Attributes belong to the node, not to the machine: the same physical machine
// hosting two nodes has two attribute sets, and deleting a node drops its set.
// Values are the JSON scalars the request carries (string, float64, bool); the
// control plane validates and bounds them before they reach the store.
type DeviceAttrStore interface {
	// SetNodeDeviceAttrs applies an update to a node's attributes: a nil value
	// deletes the attribute, any other value replaces it. Attributes not named
	// in the update are left unchanged. It fails if the node is unknown.
	SetNodeDeviceAttrs(id NodeID, update map[string]any) error
	// NodeDeviceAttrs returns a copy of a node's attributes, or nil when the
	// node has none.
	NodeDeviceAttrs(id NodeID) (map[string]any, error)
	// NodeDeviceAttrCounts returns how many attributes each node has, for
	// list views that must not carry every value.
	NodeDeviceAttrCounts() (map[NodeID]int, error)
}
