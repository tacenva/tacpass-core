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

func validateVaultAccess(
	vaultAccess *entity.VaultAccess,
	requireID bool,
) error {
	if requireID && strings.TrimSpace(vaultAccess.ID) == "" {
		return ErrNotFound
	}

	vaultAccess.ID = strings.TrimSpace(vaultAccess.ID)
	vaultAccess.VaultID = strings.TrimSpace(vaultAccess.VaultID)
	vaultAccess.PermissionID = strings.TrimSpace(vaultAccess.PermissionID)
	vaultAccess.VaultKey = strings.TrimSpace(vaultAccess.VaultKey)

	if vaultAccess.VaultID == "" {
		return ErrVaultIDEmpty
	}

	if vaultAccess.PermissionID == "" {
		return ErrPermissionIDEmpty
	}

	if vaultAccess.VaultKey == "" {
		return ErrVaultKeyEmpty
	}

	return nil
}

func (s *Service) CreateBulk(
	values []entity.VaultAccess,
) ([]entity.VaultAccess, error) {
	if len(values) == 0 {
		return values, nil
	}

	vaultAccesses := make([]*entity.VaultAccess, len(values))

	for i := range values {
		if err := validateVaultAccess(&values[i], false); err != nil {
			return nil, err
		}

		vaultAccesses[i] = &values[i]
	}

	if err := s.repository.CreateBulk(vaultAccesses); err != nil {
		return nil, err
	}

	return values, nil
}

func (s *Service) UpdateBulk(
	values []entity.VaultAccess,
) error {
	if len(values) == 0 {
		return nil
	}

	vaultAccesses := make([]*entity.VaultAccess, len(values))

	for i := range values {
		if err := validateVaultAccess(&values[i], true); err != nil {
			return err
		}

		vaultAccesses[i] = &values[i]
	}

	return s.repository.UpdateBulk(vaultAccesses)
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
