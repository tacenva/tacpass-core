package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tacenva/database"
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
	vaultRecordService *vaultrecord.RawService
	vaultaccessService *vaultaccess.Service
	permissionService  *permission.Service
	syncService        *sync.Service
}

func NewService(
	repository *repository,
	tacenvaDB *database.DB,
	vaultaccessService *vaultaccess.Service,
	permissionService *permission.Service,
	syncService *sync.Service,
) *Service {
	return &Service{
		repository: repository,
		vaultRecordService: vaultrecord.NewRawService(
			syncService,
			vaultaccessService,
		),
		vaultaccessService: vaultaccessService,
		permissionService:  permissionService,
		syncService:        syncService,
	}
}

func (s *Service) GetVaultRecordRawService() *vaultrecord.RawService {
	return s.vaultRecordService
}

func (s *Service) Create(
	authUser *entity.User,
	vaultDir string,
	name string,
) (*entity.VaultAccess, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	name = strings.TrimSpace(name)

	if name == "" {
		return nil, ErrNameEmpty
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
	}

	permissionList, err := s.permissionService.ListWithApprovedUsers()
	if err != nil {
		return nil, err
	}

	vault := &entity.Vault{
		Name: name,
	}

	userIDs := uniqueUserIDsFromPermissions(
		permissionList,
		authUser.ID,
	)

	var newVaultAccessList []entity.VaultAccess

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Create(tx, vault); err != nil {
			return err
		}

		vaultAccessList := make(
			[]entity.VaultAccess,
			0,
			len(permissionList),
		)

		for _, permissionData := range permissionList {
			keyPair := keyring.FromPublicKey(
				permissionData.PublicKey,
			)

			sealedVaultKey, err := keyPair.Seal(
				[]byte(vaultKey),
			)
			if err != nil {
				return err
			}

			vaultAccessList = append(
				vaultAccessList,
				entity.VaultAccess{
					VaultID:      vault.ID,
					PermissionID: permissionData.ID,
					VaultKey:     sealedVaultKey,
				},
			)
		}

		newVaultAccessList, err = s.vaultaccessService.CreateBulkTx(
			tx,
			vaultAccessList,
		)
		if err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			syncEntityVault,
			vault.ID,
			sync.OperationCreate,
			userIDs,
		); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	if err := s.vaultRecordService.Init(
		vaultDir,
		vault.ID,
		vaultKey,
	); err != nil {
		return nil, err
	}

	for _, data := range newVaultAccessList {
		if data.PermissionID == authUser.PermissionID {
			data.Vault = *vault

			return &data, nil
		}
	}

	return nil, ErrNotFound
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

func (s *Service) Update(
	authUser *entity.User,
	id string,
	name string,
) (*entity.Vault, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)

	if id == "" {
		return nil, ErrNotFound
	}

	if name == "" {
		return nil, ErrNameEmpty
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if vault == nil {
		return nil, ErrNotFound
	}

	userIDs, err := s.userIDsByVaultID(vault.ID, authUser.ID)
	if err != nil {
		return nil, err
	}

	vault.Name = name

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Update(tx, vault); err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			syncEntityVault,
			vault.ID,
			sync.OperationUpdate,
			userIDs,
		)
	})

	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) Delete(
	authUser *entity.User,
	vaultDir string,
	id string,
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

	userIDs, err := s.userIDsByVaultID(vault.ID, authUser.ID)
	if err != nil {
		return err
	}

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Delete(
			tx,
			vault.ID,
		); err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			syncEntityVault,
			vault.ID,
			sync.OperationDelete,
			userIDs,
		)
	})

	if err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		vaultDir,
		vault.ID,
	); err != nil {
		return err
	}

	return nil
}

func (s *Service) userIDsByVaultID(
	vaultID string,
	excludeUserID string,
) ([]string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrNotFound
	}

	vaultAccessList, err := s.vaultaccessService.FindByVaultID(
		vaultID,
	)
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, 0)
	seen := make(map[string]struct{})

	for _, vaultAccess := range vaultAccessList {
		for _, vaultAccessUser := range vaultAccess.Permission.Users {
			if _, ok := seen[vaultAccessUser.ID]; ok {
				continue
			}
			seen[vaultAccessUser.ID] = struct{}{}

			if vaultAccessUser.ID == "" {
				continue
			}

			if vaultAccessUser.ID == excludeUserID {
				continue
			}

			if vaultAccessUser.Status != entity.UserStatusApproved {
				continue
			}

			userIDs = append(
				userIDs,
				vaultAccessUser.ID,
			)
		}
	}

	return userIDs, nil
}

func uniqueUserIDsFromPermissions(
	permissionList []entity.Permission,
	excludeUserID string,
) []string {
	userIDs := make([]string, 0)
	seen := make(map[string]struct{})

	for _, permissionData := range permissionList {
		for _, user := range permissionData.Users {
			if _, ok := seen[user.ID]; ok {
				continue
			}
			seen[user.ID] = struct{}{}

			if user.ID == "" {
				continue
			}

			if user.ID == excludeUserID {
				continue
			}

			if user.Status != entity.UserStatusApproved {
				continue
			}

			userIDs = append(
				userIDs,
				user.ID,
			)
		}
	}

	return userIDs
}

func (s *Service) IsVaultAccesible(
	vaultID string,
	permissionID string,
) (bool, error) {
	return s.vaultaccessService.IsVaultAccesible(
		vaultID,
		permissionID,
	)
}

func (s *Service) PendingCount(
	authUser *entity.User,
) (int64, error) {
	if authUser == nil || authUser.ID == "" {
		return 0, ErrPermission
	}

	return s.syncService.PendingCount(
		authUser.ID,
		syncEntityVault,
	)
}

type PendingVaultChange struct {
	SyncChange  sync.SyncChange     `json:"sync_change"`
	VaultAccess *entity.VaultAccess `json:"vault_access,omitempty"`
}

func (s *Service) GetPendingChanges(
	authUser *entity.User,
) ([]PendingVaultChange, error) {
	if authUser == nil || authUser.ID == "" {
		return nil, ErrPermission
	}

	changes, err := s.syncService.GetPendingChanges(
		authUser.ID,
		syncEntityVault,
		500,
	)
	if err != nil {
		return nil, err
	}

	fmt.Printf("=== GetPendingChanges ===\n")
	fmt.Printf("authUser.ID: %s\n", authUser.ID)
	fmt.Printf("authUser.PermissionID: %s\n", authUser.PermissionID)
	fmt.Printf("changes count: %d\n", len(changes))

	for i, change := range changes {
		fmt.Printf(
			"change[%d]: ID=%s Entity=%s EntityID=%s Operation=%s\n",
			i,
			change.ID,
			change.Entity,
			change.EntityID,
			change.Operation,
		)
	}

	result := make([]PendingVaultChange, 0, len(changes))

	for _, change := range changes {
		item := PendingVaultChange{
			SyncChange: change,
		}

		if change.Operation != sync.OperationDelete {
			vaultAccessList, err := s.vaultaccessService.FindByVaultID(
				change.EntityID,
			)
			if err != nil {
				return nil, err
			}

			fmt.Printf(
				"vaultAccess for vaultID=%s: count=%d\n",
				change.EntityID,
				len(vaultAccessList),
			)

			for i := range vaultAccessList {
				fmt.Printf(
					"vaultAccess[%d]: ID=%s VaultID=%s PermissionID=%s\n",
					i,
					vaultAccessList[i].ID,
					vaultAccessList[i].VaultID,
					vaultAccessList[i].PermissionID,
				)

				if vaultAccessList[i].PermissionID != authUser.PermissionID {
					continue
				}

				item.VaultAccess = &vaultAccessList[i]
				break
			}

			if item.VaultAccess == nil {
				fmt.Printf(
					"NO MATCH: vaultID=%s permissionID=%s\n",
					change.EntityID,
					authUser.PermissionID,
				)
				continue
			}
		}

		result = append(result, item)

		fmt.Printf(
			"result append: index=%d changeID=%s operation=%s vaultAccessNil=%t\n",
			len(result)-1,
			item.SyncChange.ID,
			item.SyncChange.Operation,
			item.VaultAccess == nil,
		)
	}

	fmt.Printf("=== FINAL RESULT ===\n")
	fmt.Printf("result count: %d\n", len(result))

	for i, item := range result {
		fmt.Printf(
			"result[%d]: changeID=%s Entity=%s EntityID=%s Operation=%s\n",
			i,
			item.SyncChange.ID,
			item.SyncChange.Entity,
			item.SyncChange.EntityID,
			item.SyncChange.Operation,
		)

		if item.VaultAccess != nil {
			fmt.Printf(
				"  VaultAccess: ID=%s VaultID=%s PermissionID=%s VaultName=%s\n",
				item.VaultAccess.ID,
				item.VaultAccess.VaultID,
				item.VaultAccess.PermissionID,
				item.VaultAccess.Vault.Name,
			)
		} else {
			fmt.Printf("  VaultAccess: nil\n")
		}
	}

	return result, nil
}

func (s *Service) MarkChangesSynced(
	authUser *entity.User,
	changeIDs []string,
) error {
	if authUser == nil || authUser.ID == "" {
		return ErrPermission
	}

	if len(changeIDs) == 0 {
		return nil
	}

	return s.syncService.Transaction(func(tx *gorm.DB) error {
		if err := s.syncService.MarkSynced(
			tx,
			authUser.ID,
			syncEntityVault,
			changeIDs,
		); err != nil {
			return err
		}

		return s.syncService.CleanupChanges(tx)
	})
}
