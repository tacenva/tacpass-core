package contract

import (
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacpass-core/entity"
)

type VaultID = string

type VaultChangeData struct {
	Vault           entity.Vault         `json:"vault,omitempty"`
	VaultAccessList []entity.VaultAccess `json:"vault_accesses,omitempty"`
}

type PendingVaultChange struct { // restructure sih ini, ada perubahan khusus vault, ada khusus vaultaccess
	SyncChanges         []tacenvaentity.SyncChange  `json:"sync_changes"`
	VaultChangeDataList map[VaultID]VaultChangeData `json:"vault_change_data_list,omitempty"`
}

type PendingVaultRecordChange struct {
	SyncChanges      []tacenvaentity.SyncChange `json:"sync_changes"`
	EncryptedRecords map[string][]byte          `json:"encrypted_records,omitempty"`
}

type PendingTotalChanges struct {
	Count int64 `json:"count"`
}
