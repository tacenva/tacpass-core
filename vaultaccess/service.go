package vaultaccess

import (
	"errors"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

var (
	ErrNotFound          = errors.New("vault access not found")
	ErrVaultIDEmpty      = errors.New("vault ID cannot be empty")
	ErrPermissionIDEmpty = errors.New("permission ID cannot be empty")
	ErrVaultKeyEmpty     = errors.New("vault key cannot be empty")
)

type Service struct {
	repository *repository
}

func NewService(repository *repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Create(
	vaultID string,
	permissionID string,
	vaultKey string,
) (*entity.VaultAccess, error) {
	vaultID = strings.TrimSpace(vaultID)
	permissionID = strings.TrimSpace(permissionID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	if permissionID == "" {
		return nil, ErrPermissionIDEmpty
	}

	if vaultKey == "" {
		return nil, ErrVaultKeyEmpty
	}

	vaultAccess := &entity.VaultAccess{
		VaultID:      vaultID,
		PermissionID: permissionID,
		VaultKey:     vaultKey,
	}

	if err := s.repository.Create(vaultAccess); err != nil {
		return nil, err
	}

	return vaultAccess, nil
}

func (s *Service) IsVaultAccesible(
	vaultID string,
	permissionID string,
) (bool, error) {
	vaultAccess, err := s.repository.FindByVaultAndPermission(
		vaultID,
		permissionID,
	)
	if err != nil {
		return false, err
	}

	if vaultAccess == nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) GetVaultKey(
	vaultID string,
	permissionID string,
	keyPair *keyring.KeyPair,
) ([]byte, error) {
	vaultID = strings.TrimSpace(vaultID)
	permissionID = strings.TrimSpace(permissionID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	if permissionID == "" {
		return nil, ErrPermissionIDEmpty
	}

	vaultAccess, err := s.repository.FindByVaultAndPermission(
		vaultID,
		permissionID,
	)
	if err != nil {
		return nil, err
	}

	vaultKey, err := keyPair.Open(vaultAccess.VaultKey)
	if err != nil {
		return nil, err
	}

	return vaultKey, nil
}

func (s *Service) List() ([]entity.VaultAccess, error) {
	return s.repository.FindAll()
}

func (s *Service) Delete(id string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	return s.repository.Delete(id)
}
