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
	tacenvaDB          *database.DB
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
		repository:         repository,
		tacenvaDB:          tacenvaDB,
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

	if err := s.repository.Create(vault); err != nil {
		return nil, err
	}

	vaultAccessList := make([]entity.VaultAccess, 0, len(permissionList))

	for _, permissionData := range permissionList {
		keyPair := keyring.FromPublicKey(permissionData.PublicKey)

		sealedVaultKey, err := keyPair.Seal([]byte(vaultKey))
		if err != nil {
			return nil, err
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

	newVaultAccessList, err := s.vaultaccessService.CreateBulk(vaultAccessList)
	if err != nil {
		return nil, err
	}

	_, err = s.tacenvaDB.File(
		vault.ID,
		vaultKey,
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return nil, err
	}

	userIDs := uniqueUserIDsFromPermissions(permissionList)

	// TODO:
	// Ganti nil dengan transaction *gorm.DB yang mencakup
	// mutation Vault + VaultAccess + SyncChange.
	if err := s.syncService.RecordChange(
		(*gorm.DB)(nil),
		syncEntityVault,
		vault.ID,
		sync.OperationCreate,
		userIDs,
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

	vault.Name = name

	if err := s.repository.Update(vault); err != nil {
		return nil, err
	}

	userIDs, err := s.userIDsByVaultID(vault.ID)
	if err != nil {
		return nil, err
	}

	// TODO:
	// Ganti nil dengan transaction *gorm.DB yang sama
	// dengan transaction update Vault.
	if err := s.syncService.RecordChange(
		(*gorm.DB)(nil),
		syncEntityVault,
		vault.ID,
		sync.OperationUpdate,
		userIDs,
	); err != nil {
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

	// Ambil user IDs sebelum VaultAccess ikut terhapus.
	userIDs, err := s.userIDsByVaultID(vault.ID)
	if err != nil {
		return err
	}

	if err := s.tacenvaDB.Delete(vault.ID); err != nil {
		return err
	}

	if err := s.repository.Delete(vault.ID); err != nil {
		return err
	}

	// TODO:
	// Ganti nil dengan transaction *gorm.DB yang sama
	// dengan transaction delete Vault.
	if err := s.syncService.RecordChange(
		(*gorm.DB)(nil),
		syncEntityVault,
		vault.ID,
		sync.OperationDelete,
		userIDs,
	); err != nil {
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
	return s.vaultaccessService.IsVaultAccesible(vaultID, permissionID)
}
