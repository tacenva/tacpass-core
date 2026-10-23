package contract

import (
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/sync"
)

type VaultID = string

type VaultChangeData struct {
	Vault           entity.Vault         `json:"vault,omitempty"`
	VaultAccessList []entity.VaultAccess `json:"vault_accesses,omitempty"`
}

type PendingVaultChange struct { // restructure sih ini, ada perubahan khusus vault, ada khusus vaultaccess
	SyncChanges         []sync.SyncChange           `json:"sync_changes"`
	VaultChangeDataList map[VaultID]VaultChangeData `json:"vault_change_data_list,omitempty"`
}

type PendingVaultRecordChange struct {
	SyncChanges      []sync.SyncChange `json:"sync_changes"`
	EncryptedRecords map[string][]byte `json:"encrypted_records,omitempty"`
}

type PendingTotalChanges struct {
	Count int64 `json:"count"`
}
