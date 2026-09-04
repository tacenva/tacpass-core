package vaultaccess

import (
	"errors"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
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

func (s *Service) Get(id string) (*entity.VaultAccess, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, ErrNotFound
	}

	vaultAccess, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	return vaultAccess, nil
}

func (s *Service) GetByVaultAndPermission(
	vaultID string,
	permissionID string,
) (*entity.VaultAccess, error) {
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

	return vaultAccess, nil
}

func (s *Service) List() ([]entity.VaultAccess, error) {
	return s.repository.FindAll()
}

func (s *Service) ListByVaultID(
	vaultID string,
) ([]entity.VaultAccess, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	return s.repository.FindByVaultID(vaultID)
}

func (s *Service) ListByPermissionID(
	permissionID string,
) ([]entity.VaultAccess, error) {
	permissionID = strings.TrimSpace(permissionID)

	if permissionID == "" {
		return nil, ErrPermissionIDEmpty
	}

	return s.repository.FindByPermissionID(permissionID)
}

func (s *Service) Update(
	id string,
	vaultID string,
	permissionID string,
	vaultKey string,
) (*entity.VaultAccess, error) {
	id = strings.TrimSpace(id)
	vaultID = strings.TrimSpace(vaultID)
	permissionID = strings.TrimSpace(permissionID)

	if id == "" {
		return nil, ErrNotFound
	}

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	if permissionID == "" {
		return nil, ErrPermissionIDEmpty
	}

	if vaultKey == "" {
		return nil, ErrVaultKeyEmpty
	}

	vaultAccess, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	vaultAccess.VaultID = vaultID
	vaultAccess.PermissionID = permissionID
	vaultAccess.VaultKey = vaultKey

	if err := s.repository.Update(vaultAccess); err != nil {
		return nil, err
	}

	return vaultAccess, nil
}

func (s *Service) Delete(id string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	return s.repository.Delete(id)
}
