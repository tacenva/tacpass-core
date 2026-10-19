package vault

import (
	"encoding/json"
	"errors"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/sync"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/util/credential"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"gorm.io/gorm"
)

var (
	ErrNotFound   = errors.New("vault not found")
	ErrNameEmpty  = errors.New("vault name cannot be empty")
	ErrPermission = errors.New("permission denied")
)

const syncEntityVault = "vault"

type Service struct {
	repository         *repository
	vaultaccessService *vaultaccess.Service
	vaultRecordService *vaultrecord.Service
	permissionService  *permission.Service
	syncService        *sync.Service
}

func NewService(
	repository *repository,
	vaultaccessService *vaultaccess.Service,
	permissionService *permission.Service,
	syncService *sync.Service,
) *Service {
	return &Service{
		repository: repository,
		vaultRecordService: vaultrecord.NewService(
			syncService,
		),
		vaultaccessService: vaultaccessService,
		permissionService:  permissionService,
		syncService:        syncService,
	}
}

func (s *Service) GetVaultRecordService() *vaultrecord.Service {
	return s.vaultRecordService
}

func (s *Service) VaultAccessList(
	authUser *entity.User,
) ([]entity.VaultAccess, error) {
	if authUser == nil {
		return nil, ErrPermission
	}

	vaultAccessList, err := s.repository.FindAccessible(
		authUser.PermissionID,
	)
	if err != nil {
		return nil, err
	}

	return vaultAccessList, nil
}

func (s *Service) ConnectedPublicKeys(
	authUser *entity.User,
) ([]entity.Permission, error) {
	return s.permissionService.ConnectedPublicKeys(authUser)
}

func (s *Service) CreateOnSoT(
	authUser *entity.User,
	vaultDir string,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) (*entity.VaultAccess, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	var vaData *entity.VaultAccess
	err := s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Create(tx, vault); err != nil {
			return err
		}

		connectedPermission, err := s.ConnectedPublicKeys(authUser)
		if err != nil {
			return err
		}

		vaultKey, err := credential.Generate(32)
		if err != nil {
			return err
		}

		vaList := make(
			[]entity.VaultAccess,
			0,
			len(connectedPermission),
		)

		for _, permissionData := range connectedPermission {
			keyPair := keyring.FromPublicKey(permissionData.PublicKey)
			wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))
			if err != nil {
				break
			}

			vaList = append(vaList, entity.VaultAccess{
				VaultID:      vault.ID,
				PermissionID: permissionData.ID,
				VaultKey:     wrappedVaultKey,
			})
		}

		vaListRes, err := s.vaultaccessService.CreateBulkTx(tx, vaList)
		for _, vaPointer := range vaListRes {
			if vaPointer.PermissionID == authUser.PermissionID {
				vaData = &vaList[len(vaList)-1]
				vaData.Vault = *vault
				err = s.vaultRecordService.Init(vaultDir, vaData.VaultID, vaultKey)
				break
			}
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationCreate,
			sotID,
		)
	})
	return vaData, err
}

func (s *Service) CreateOnReplica(
	vaultDir string,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
	dbFile *database.DatabaseFile,

	keypair *keyring.KeyPair,
) (*entity.VaultAccess, error) {
	vault.Name = strings.TrimSpace(vault.Name)
	if vault.Name == "" {
		return nil, ErrNameEmpty
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
	}

	if vault.ID == "" {
		vault.ID = ulid.Make().String()
	}

	keyPair := keyring.FromPublicKey(keypair.PublicKey)
	wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))

	vaultAccess := &entity.VaultAccess{
		ID:       ulid.Make().String(),
		VaultID:  vault.ID,
		VaultKey: wrappedVaultKey,
		Vault:    *vault,
	}

	if _, err := dbFile.Insert(vaultAccess); err != nil {
		return nil, err
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		sync.OperationCreate,
		sotID,
	); err != nil {
		return nil, err
	}
	err = s.vaultRecordService.Init(vaultDir, vault.ID, vaultKey)
	return vaultAccess, err
}

func (s *Service) UpdateOnSoT(
	authUser *entity.User,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) (*entity.Vault, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return nil, ErrNotFound
	}

	if vault.Name == "" {
		return nil, ErrNameEmpty
	}

	_, err := s.repository.FindByID(vault.ID)
	if err != nil {
		return nil, err
	}

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Update(tx, vault); err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationUpdate,
			sotID,
		)
	})

	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) findVAOnReplica(
	vaultID string,
	dbFile *database.DatabaseFile,
) (*entity.VaultAccess, error) {
	var vaData entity.VaultAccess
	err := dbFile.FindFirstWhere(&vaData, func(data map[string]any) bool {
		vaultData, ok := data["vault"].(map[string]any)
		if !ok {
			return false
		}

		id, ok := vaultData["id"].(string)
		if !ok {
			return false
		}

		// vaultDataJSON, _ := json.MarshalIndent(vaultData, "", "  ")
		// log.Printf("[DEBUG] vaultData:\n%s", string(vaultDataJSON))

		return vaultID == id
	})
	return &vaData, err
}

func (s *Service) UpdateOnReplica(
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) (*entity.Vault, error) {
	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return nil, ErrNotFound
	}

	if vault.Name == "" {
		return nil, ErrNameEmpty
	}

	vaData, err := s.findVAOnReplica(vault.ID, dbFile)
	if err != nil {
		return nil, err
	}

	vaData.Vault = *vault
	err = dbFile.Update(vaData)
	if err != nil {
		return nil, err
	}

	err = s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vaData.Vault.ID,
		sync.OperationUpdate,
		sotID,
	)
	if err != nil {
		return nil, err
	}

	return &vaData.Vault, nil
}

func (s *Service) DeleteOnSoT(
	authUser *entity.User,
	vaultDir string,
	id string,
	sotID string,
	lastChangeID *string,
) error {
	if authUser == nil || !authUser.HasWritePermission() {
		return ErrPermission
	}

	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if vault == nil {
		return ErrNotFound
	}

	return s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Delete(
			tx,
			vault.ID,
		); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationDelete,
			sotID,
		); err != nil {
			return err
		}

		return s.vaultRecordService.Destroy(
			vaultDir,
			vault.ID,
		)
	})
}

func (s *Service) DeleteOnReplica(
	vaultDir string,
	id string,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	vaData, err := s.findVAOnReplica(id, dbFile)
	// log.Printf("[DEBUG] vaData: %+v, err: %v", vaData, err)
	if err != nil {
		return err
	}

	_, err = dbFile.Delete(vaData.ID)
	if err != nil {
		return err
	}

	err = s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		id,
		sync.OperationDelete,
		sotID,
	)
	if err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		vaultDir,
		id,
	); err != nil {
		return err
	}

	return nil
}

func (s *Service) GetSyncLatestChangeId(
	sotID string,
) (string, error) {
	syncState, err := s.syncService.GetSyncState(
		sotID,
		syncEntityVault,
	)

	return syncState.LastChangeID, err
}

func (s *Service) GetChangesAfterOnSoT(
	authUser *entity.User,
	sotID string,
	startID string,
	limit int,
) ([]contract.PendingVaultChange, error) {
	if authUser == nil || authUser.ID == "" {
		return nil, ErrPermission
	}

	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		startID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	result := make(
		[]contract.PendingVaultChange,
		0,
		len(changes),
	)

	for _, change := range changes {
		item := contract.PendingVaultChange{
			SyncChange: change,
		}

		vault, err := s.repository.FindByID(
			change.EntityID,
		)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				vault = &entity.Vault{
					ID: change.EntityID,
				}
				err = nil
			} else {
				return nil, err
			}
		}

		item.Vault = vault
		if change.Operation != sync.OperationDelete {
			vaultAccessList, err := s.vaultaccessService.FindByVaultID(
				change.EntityID,
				authUser.PermissionID,
			)
			log.Printf("VaultID : %s", change.EntityID)
			data, _ := json.MarshalIndent(vaultAccessList, "", "  ")
			log.Printf("[DEBUG] FindByVaultID result:\n%s", string(data))

			if err != nil {
				return nil, err
			}

			item.VaultAccessList = vaultAccessList

			// for _, vaData := range vaultAccessList {
			// 	if vaData.PermissionID != authUser.PermissionID {
			// 		continue
			// 	}

			// 	item.VaultAccessList = append(item.VaultAccessList, entity.VaultAccess{
			// 		ID:           vaData.ID,
			// 		VaultID:      vaData.VaultID,
			// 		PermissionID: vaData.PermissionID,
			// 		VaultKey:     vaData.VaultKey,
			// 	})

			// 	break
			// }
		}

		result = append(result, item)
	}

	return result, nil
}

func (s *Service) GetChangesAfterOnReplica(
	sotID string,
	startID string,
	limit int,
	dbFile *database.DatabaseFile,
) ([]contract.PendingVaultChange, error) {
	// log.Printf(
	// 	"[DEBUG] GetChangesAfterOnReplica START: sotID=%s startID=%s limit=%d",
	// 	sotID, startID, limit,
	// )

	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		startID,
		limit,
	)
	if err != nil {
		// log.Printf("[DEBUG] GetChangesAfter failed: %v", err)
		return nil, err
	}

	// changesJSON, err := json.MarshalIndent(changes, "", "  ")
	// if err != nil {
	// 	log.Printf("[DEBUG] Failed to marshal changes: %v", err)
	// } else {
	// 	log.Printf(
	// 		"[DEBUG] GetChangesAfter returned %d changes:\n%s",
	// 		len(changes),
	// 		string(changesJSON),
	// 	)
	// }

	result := make([]contract.PendingVaultChange, 0, len(changes))

	for _, change := range changes {
		// log.Printf(
		// 	"[DEBUG] Processing change[%d]: ID=%s SotID=%s Entity=%s EntityID=%s Operation=%s",
		// 	i,
		// 	change.ID,
		// 	change.SotID,
		// 	change.Entity,
		// 	change.EntityID,
		// 	change.Operation,
		// )

		item := contract.PendingVaultChange{
			SyncChange: change,
		}

		if change.Operation != sync.OperationDelete {
			var vaFound entity.VaultAccess

			err := dbFile.FindFirstWhere(
				&vaFound,
				func(data map[string]any) bool {
					vaultID, ok := data["vault_id"]
					return ok && vaultID == change.EntityID
				},
			)

			if err != nil {
				if err != database.RecordNotFound {
					return nil, err
				}

				// log.Printf(
				// 	"[DEBUG] VaultAccess not found, appending change without VaultAccess: changeID=%s vaultID=%s",
				// 	change.ID,
				// 	change.EntityID,
				// )
			} else {
				item.VaultAccessList = append(item.VaultAccessList,
					entity.VaultAccess{
						ID:       vaFound.ID,
						VaultID:  vaFound.VaultID,
						VaultKey: vaFound.VaultKey,
					},
				)

				item.Vault = &vaFound.Vault
			}
		}

		// Tetap append meskipun VaultAccess tidak ditemukan.
		result = append(result, item)
		// log.Printf(
		// 	"[DEBUG] Item appended: changeID=%s resultCount=%d",
		// 	change.ID,
		// 	len(result),
		// )
	}

	// resultJSON, err := json.MarshalIndent(result, "", "  ")
	// if err != nil {
	// 	log.Printf("[DEBUG] Failed to marshal final result: %v", err)
	// } else {
	// 	log.Printf(
	// 		"[DEBUG] GetChangesAfterOnReplica RESULT (%d items):\n%s",
	// 		len(result),
	// 		string(resultJSON),
	// 	)
	// }

	// log.Printf(
	// 	"[DEBUG] GetChangesAfterOnReplica END: inputChanges=%d resultItems=%d",
	// 	len(changes),
	// 	len(result),
	// )

	return result, nil
}

func (s *Service) GetChangeCount(
	sotID string,
	startID string,
) (int64, error) {
	return s.syncService.GetChangeCount(
		sotID,
		syncEntityVault,
		startID,
	)
}

func (s *Service) MergePendingVaultChange(
	base []contract.PendingVaultChange,
	comp []contract.PendingVaultChange,
) []contract.PendingVaultChange {
	// // Debug: tampilkan isi base sebelum proses merge
	// baseJSON, err := json.MarshalIndent(base, "", "  ")
	// if err != nil {
	// 	log.Printf("[DEBUG] MergePendingVaultChange: gagal marshal base: %v", err)
	// } else {
	// 	log.Printf("[DEBUG] MergePendingVaultChange: BASE sebelum merge:\n%s", string(baseJSON))
	// }

	// // Debug: tampilkan isi comp sebelum proses merge
	// compJSON, err := json.MarshalIndent(comp, "", "  ")
	// if err != nil {
	// 	log.Printf("[DEBUG] MergePendingVaultChange: gagal marshal comp: %v", err)
	// } else {
	// 	log.Printf("[DEBUG] MergePendingVaultChange: COMP sebelum merge:\n%s", string(compJSON))
	// }

	// log.Printf("[DEBUG][Merge] START base=%d comp=%d\n", len(base), len(comp))

	clonedBase := slices.Clone(base)
	merged := make(map[string]contract.PendingVaultChange)

	for _, change := range clonedBase {
		// log.Printf(
		// 	"[DEBUG][Merge][BASE][%d] ID=%s EntityID=%s Operation=%s VaultNil=%t\n",
		// 	i,
		// 	change.SyncChange.ID,
		// 	change.SyncChange.EntityID,
		// 	change.SyncChange.Operation,
		// 	change.Vault == nil,
		// )

		vaultID := change.SyncChange.EntityID
		existing, exists := merged[vaultID]

		if exists && (existing.SyncChange.Operation == sync.OperationDelete ||
			(existing.SyncChange.Operation == sync.OperationCreate &&
				change.SyncChange.Operation == sync.OperationUpdate)) {
			continue
		}

		if !exists || change.SyncChange.ID > existing.SyncChange.ID {
			// log.Printf(
			// 	"[DEBUG][Merge][BASE][%d] SET vaultID=%s previousID=%s newID=%s\n",
			// 	i, vaultID, existing.SyncChange.ID, change.SyncChange.ID,
			// )
			merged[vaultID] = change
		} else {
			// log.Printf(
			// 	"[DEBUG][Merge][BASE][%d] SKIP: incoming ID=%s <= existing ID=%s\n",
			// 	i, change.SyncChange.ID, existing.SyncChange.ID,
			// )
		}
	}

	for _, change := range comp {
		// log.Printf(
		// 	"[DEBUG][Merge][COMP][%d] ID=%s EntityID=%s Operation=%s VaultNil=%t\n",
		// 	i,change
		// 	change.SyncChange.ID,
		// 	change.SyncChange.EntityID,
		// 	change.SyncChange.Operation,
		// 	change.Vault == nil,
		// )

		if change.Vault == nil {
			// log.Printf("[DEBUG][Merge][COMP][%d] SKIP: Vault is nil\n", i)
			continue
		}

		vaultID := change.SyncChange.EntityID
		existing, exists := merged[vaultID]

		if !exists {
			// log.Printf(
			// 	"[DEBUG][Merge][COMP][%d] SKIP: vaultID=%s does not exist in base merge\n",
			// 	i, vaultID,
			// )
			continue
		}

		if existing.SyncChange.Operation == sync.OperationDelete {
			// log.Printf(
			// 	"[DEBUG][Merge][COMP][%d] SKIP: existing change is DELETE, vaultID=%s\n",
			// 	i, vaultID,
			// )
			continue
		}

		if change.SyncChange.ID > existing.SyncChange.ID {
			// log.Printf(
			// 	"[DEBUG][Merge][COMP][%d] REPLACE vaultID=%s oldID=%s newID=%s\n",
			// 	i,
			// 	vaultID,
			// 	existing.SyncChange.ID,
			// 	change.SyncChange.ID,
			// )
			merged[vaultID] = change
		} else {
			// log.Printf(
			// 	"[DEBUG][Merge][COMP][%d] KEEP existing vaultID=%s existingID=%s incomingID=%s\n",
			// 	i,
			// 	vaultID,
			// 	existing.SyncChange.ID,
			// 	change.SyncChange.ID,
			// )
		}
	}

	result := make([]contract.PendingVaultChange, 0, len(merged))
	for _, change := range merged {
		result = append(result, change)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].SyncChange.ID < result[j].SyncChange.ID
	})

	// for i, change := range result {
	// 	log.Printf(
	// 		"[DEBUG][Merge][RESULT][%d] ID=%s EntityID=%s Operation=%s VaultNil=%t AccessCount=%d\n",
	// 		i,
	// 		change.SyncChange.ID,
	// 		change.SyncChange.EntityID,
	// 		change.SyncChange.Operation,
	// 		change.Vault == nil,
	// 		len(change.VaultAccessList),
	// 	)
	// }

	// log.Printf("[DEBUG][Merge] END result=%d\n", len(result))

	return result
}

func (s *Service) ApplyChangeOnSoT(
	vaultChanges []contract.PendingVaultChange,
) error {
	err := s.repository.Transaction(func(tx *gorm.DB) error {
		for _, change := range vaultChanges {
			vault := change.Vault
			switch change.SyncChange.Operation {
			case sync.OperationCreate:
				if vault == nil {
					continue
				}

				if err := s.repository.Create(tx, vault); err != nil {
					return err
				}

				if err := s.vaultaccessService.CreateOrUpdateBulkTx(tx, change.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationUpdate:
				if vault == nil {
					continue
				}

				if err := s.repository.FirstOrCreate(tx, vault); err != nil {
					return err
				}

				if err := s.vaultaccessService.CreateOrUpdateBulkTx(tx, change.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationDelete:
				if err := s.repository.Delete(tx, change.SyncChange.EntityID); err != nil {
					return err
				}
			}
		}

		return nil
	})

	// if err != nil {
	// 	log.Printf("[ERROR] ApplyChangeOnSoT failed: %v", err)
	// }

	return err
}

func (s *Service) ApplyChangeOnReplica(
	vaultChanges []contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	for _, change := range vaultChanges {
		changeJSON, err := json.MarshalIndent(change, "", "  ")
		if err != nil {
			log.Printf("[DEBUG] Gagal marshal change: %v", err)
		} else {
			log.Printf("[DEBUG] ApplyChangeOnReplica change:\n%s", string(changeJSON))
		}

		var vaData entity.VaultAccess
		if len(change.VaultAccessList) > 0 {
			vaData = change.VaultAccessList[0]
		}
		vaData.Vault = *change.Vault

		switch change.SyncChange.Operation {
		case sync.OperationCreate:
			_, err := dbFile.Insert(&vaData)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			err := dbFile.Update(&vaData)
			if err != nil {
				if err == database.RecordNotFound {
					continue
				}
				return err
			}

		case sync.OperationDelete:
			foundVa, err := s.findVAOnReplica(
				change.Vault.ID,
				dbFile,
			)
			if err != nil {
				if err == database.RecordNotFound {
					continue
				}
				return err
			}

			_, err = dbFile.Delete(foundVa.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) insertSyncChanges(
	sotID string,
	vaultChanges []contract.PendingVaultChange,
) error {
	if len(vaultChanges) == 0 {
		return nil
	}

	syncChanges := make([]sync.SyncChange, len(vaultChanges))

	for i, change := range vaultChanges {
		syncChanges[i] = change.SyncChange
		syncChanges[i].SotID = sotID
	}

	return s.syncService.InsertSyncChanges(
		sotID,
		syncEntityVault,
		syncChanges,
	)
}

func (s *Service) SyncOnReplica(
	sotID string,
	replicaChanges []contract.PendingVaultChange,
	sotChanges []contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	changes := s.MergePendingVaultChange(sotChanges, replicaChanges)
	if err := s.ApplyChangeOnReplica(changes, dbFile); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, sotChanges)
}

func (s *Service) SyncOnSoT(
	sotID string,
	changes []contract.PendingVaultChange,
) error {
	if err := s.ApplyChangeOnSoT(changes); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, changes)
}

func (s *Service) SetSyncStateToBeLastest(
	sotID string,
) error {
	return s.repository.Transaction(func(tx *gorm.DB) error {
		return s.syncService.SetSyncStateToBeLastest(
			tx,
			sotID,
			syncEntityVault,
		)
	})
}
