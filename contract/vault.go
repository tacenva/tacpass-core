package contract

import (
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/sync"
)

type PendingVaultChange struct {
	SyncChange      sync.SyncChange      `json:"sync_change"`
	Vault           *entity.Vault        `json:"vault,omitempty"`
	VaultAccessList []entity.VaultAccess `json:"vault_accesses,omitempty"`
}

type PendingVaultRecordChange struct {
	SyncChange sync.SyncChange `json:"sync_change"`
	RecordID   string          `json:"reco,omitempty"`
	Record     []byte          `json:"record,omitempty"`
}
