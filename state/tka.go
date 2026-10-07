package state

// Tailnet lock (TKA) bookkeeping for one tailnet.
//
// The AUM chain itself lives in the tailnet's TKA storage (a tailchonk); this
// record only carries the control plane's view of the feature, which the
// netmap needs without opening the chain:
//
//   - never enabled: a nil MapResponse.TKAInfo (clients treat that as "this
//     tailnet has no tailnet lock").
//   - enabled: TKAInfo.Head tells clients which AUM chain to sync to.
//   - disabled after being enabled: TKAInfo.Disabled tells clients with local
//     TKA state to clear it. The netmap keeps advertising the tailnet-lock
//     capability so those clients act on it.

// TKAMeta is the durable tailnet-lock state of one tailnet.
type TKAMeta struct {
	// EverEnabled records that a chain was installed on this tailnet. It keeps
	// the capability and TKAInfo flowing after a disablement, so clients
	// holding local state can clear it.
	EverEnabled bool
	// Enabled records that tailnet lock is being enforced: a chain is
	// installed *and* every existing node was signed (the init/finish step).
	// Between a client's init/begin and init/finish the chain exists but is
	// not advertised, so the tailnet keeps working while signatures are
	// collected.
	Enabled bool
	// Disabled records that the tailnet's key authority was disabled with the
	// support disablement secret. It has no meaning before EverEnabled.
	Disabled bool
	// DisablementSecretSealed is the support disablement secret in sealed
	// form. Only the control plane, which owns the sealing key, can turn it
	// back into the secret handed to clients during bootstrap (AGENTS.md
	// section 8). Empty when the operator did not generate one.
	DisablementSecretSealed string
}

// TKAStore is the durable tailnet-lock bookkeeping, implemented next to the
// node state so a tailnet's control plane has one source of truth.
type TKAStore interface {
	// TKAMeta returns the tailnet's tailnet-lock state. The zero value means
	// tailnet lock was never enabled.
	TKAMeta() TKAMeta
	// SetTKAMeta replaces the tailnet-lock state.
	SetTKAMeta(TKAMeta) error
}
