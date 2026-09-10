package vault

import (
	"errors"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/util/credential"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpass-core/vaultaccess"
)

var (
	ErrNotFound   = errors.New("vault not found")
	ErrNameEmpty  = errors.New("vault name cannot be empty")
	ErrPermission = errors.New("permission denied")
)

type Service struct {
	repository         *repository
	tacenvaDB          *database.DB
	vaultaccessService *vaultaccess.Service
	permissionService  *permission.Service
}

func NewService(
	repository *repository,
	tacenvaDB *database.DB,
	vaultaccessService *vaultaccess.Service,
	permissionService *permission.Service,
) *Service {
	return &Service{
		repository:         repository,
		tacenvaDB:          tacenvaDB,
		vaultaccessService: vaultaccessService,
		permissionService:  permissionService,
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

	if err := s.tacenvaDB.Delete(vault.ID); err != nil {
		return err
	}

	if err := s.repository.Delete(vault.ID); err != nil {
		return err
	}

	return nil
}
