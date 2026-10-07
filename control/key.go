package control

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"tailscale.com/types/key"
)

// noiseKeyFileName is the file, inside the state directory, holding the control
// server's long-lived Noise (TS2021) machine key.
const noiseKeyFileName = "noise_private.key"

// loadOrCreateNoiseKey returns the server's Noise machine key, generating and
// persisting a new one on first use.
//
// The key is the server's long-term identity in the control protocol. It must
// be stable across restarts: clients pin it (TOFU) and will refuse to connect
// if it changes.
func loadOrCreateNoiseKey(stateDir string) (key.MachinePrivate, error) {
	path := filepath.Join(stateDir, noiseKeyFileName)

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var k key.MachinePrivate
		if err := k.UnmarshalText(bytes.TrimSpace(raw)); err != nil {
			return key.MachinePrivate{}, fmt.Errorf("parsing %s: %w", path, err)
		}
		return k, nil

	case errors.Is(err, os.ErrNotExist):
		k := key.NewMachine()

		text, err := k.MarshalText()
		if err != nil {
			return key.MachinePrivate{}, fmt.Errorf("marshalling new noise key: %w", err)
		}
		if err := os.WriteFile(path, text, 0o600); err != nil {
			return key.MachinePrivate{}, fmt.Errorf("writing %s: %w", path, err)
		}
		return k, nil

	default:
		return key.MachinePrivate{}, fmt.Errorf("reading %s: %w", path, err)
	}
}
