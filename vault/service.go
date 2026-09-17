package vault

import (
	"errors"
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
	VaultRecordService *vaultrecord.RawService
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
		VaultRecordService: vaultrecord.NewRawService(
			tacenvaDB,
			syncService,
			vaultaccessService,
		),
		vaultaccessService: vaultaccessService,
		permissionService:  permissionService,
		syncService:        syncService,
	}
}

func (s *Service) Create(
	authUser *entity.User,
	name string,
) (*entity.VaultAccess, error) {
	if !authUser.HasWritePermission() {
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

	permissionList, err := s.permissionService.List()
	if err != nil {
		return nil, err
	}

	vault := &entity.Vault{
		Name: name,
	}

	userIDs := uniqueUserIDsFromPermissions(
		permissionList,
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

	if err = s.VaultRecordService.Init(vault.ID, vaultKey); err != nil {
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
	if !authUser.HasWritePermission() {
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

	userIDs, err := s.userIDsByVaultID(vault.ID)
	if err != nil {
		return nil, err
	}

	vault.Name = name

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Update(tx, vault); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			syncEntityVault,
			vault.ID,
			sync.OperationUpdate,
			userIDs,
		); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) Delete(
	authUser *entity.User,
	id string,
) error {
	if !authUser.HasWritePermission() {
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

	// Ambil sebelum VaultAccess terhapus.
	userIDs, err := s.userIDsByVaultID(vault.ID)
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

		if err := s.syncService.RecordChange(
			tx,
			syncEntityVault,
			vault.ID,
			sync.OperationDelete,
			userIDs,
		); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := s.VaultRecordService.Delete(vault.ID, id); err != nil {
		return err
	}

	return nil
}

func (s *Service) userIDsByVaultID(
	vaultID string,
) ([]string, error) {
	vaultAccessList, err := s.vaultaccessService.FindByVaultID(
		vaultID,
	)
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, 0)
	seen := make(map[string]struct{})

	for _, vaultAccess := range vaultAccessList {
		for _, user := range vaultAccess.Permission.Users {
			if user.ID == "" {
				continue
			}

			if _, ok := seen[user.ID]; ok {
				continue
			}

			seen[user.ID] = struct{}{}

			userIDs = append(
				userIDs,
				user.ID,
			)
		}
	}

	return userIDs, nil
}

func uniqueUserIDsFromPermissions(
	permissionList []entity.Permission,
) []string {
	userIDs := make([]string, 0)
	seen := make(map[string]struct{})

	for _, permissionData := range permissionList {
		for _, user := range permissionData.Users {
			if user.ID == "" {
				continue
			}

			if _, ok := seen[user.ID]; ok {
				continue
			}

			seen[user.ID] = struct{}{}

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
	return s.syncService.PendingCount(authUser.ID, syncEntityVault)
}

type PendingVaultChange struct {
	SyncChange sync.SyncChange `json:"sync_change"`
	Vault      *entity.Vault   `json:"vault,omitempty"`
}

func (s *Service) GetPendingChanges(
	authUser *entity.User,
) ([]PendingVaultChange, error) {
	changes, err := s.syncService.GetPendingChanges(
		authUser.ID,
		syncEntityVault,
		500,
	)
	if err != nil {
		return nil, err
	}

	result := make([]PendingVaultChange, 0, len(changes))

	for _, change := range changes {
		item := PendingVaultChange{
			SyncChange: change,
		}

		if change.Operation != sync.OperationDelete {
			vault, err := s.repository.FindByID(
				change.EntityID,
			)
			if err != nil {
				return nil, err
			}

			if vault == nil {
				continue
			}

			item.Vault = vault
		}

		result = append(result, item)
	}

	return result, nil
}
