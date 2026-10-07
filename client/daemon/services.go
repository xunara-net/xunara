package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xunara/xunara/client/protocol"
)

// servicesFile is the durable service declaration inside the state directory.
// It is separate from agent.json so publishing services never rewrites the
// credential file.
const servicesFile = "services.json"

// serviceDeclaration is the on-disk shape. The wrapper leaves room for
// declaration metadata without breaking the file format.
type serviceDeclaration struct {
	Services []protocol.Service `json:"services"`
}

// LoadServices reads the agent's service declaration. A missing file returns
// an error wrapping [os.ErrNotExist]: this agent publishes no services.
func LoadServices(stateDir string) ([]protocol.Service, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, servicesFile))
	if err != nil {
		return nil, err
	}

	var decl serviceDeclaration
	if err := json.Unmarshal(raw, &decl); err != nil {
		return nil, fmt.Errorf("daemon: parsing %s: %w", servicesFile, err)
	}
	return decl.Services, nil
}

// SaveServices writes the service declaration atomically with 0600
// permissions, so a running agent picks it up on its next refresh.
func SaveServices(stateDir string, services []protocol.Service) error {
	if services == nil {
		services = []protocol.Service{}
	}
	raw, err := json.MarshalIndent(serviceDeclaration{Services: services}, "", "  ")
	if err != nil {
		return fmt.Errorf("daemon: encoding services: %w", err)
	}
	return writeFileAtomic(stateDir, servicesFile, raw)
}

// RemoveServices deletes the local declaration. It does not touch the control
// plane: callers withdraw the set first (the CLI publishes an empty set).
func RemoveServices(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, servicesFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
