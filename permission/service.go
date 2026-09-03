package permission

import (
	"errors"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/credential"
)

var (
	ErrNotFound         = errors.New("permission not found")
	ErrTokenEmpty       = errors.New("token cannot be empty")
	ErrPrivilegeInvalid = errors.New("invalid privilege")
	ErrRevoked          = errors.New("permission revoked")
)

const tokenSize = 32

type Service struct {
	repository *repository
}

func NewService(repository *repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Create(
	privilege entity.Privilege,
) (*entity.Permission, string, error) {
	if !privilege.IsValid() {
		return nil, "", ErrPrivilegeInvalid
	}

	token, err := credential.Generate(tokenSize)
	if err != nil {
		return nil, "", err
	}

	permission := &entity.Permission{
		Privilege: privilege,
		Token:     credential.Hash(token),
		Revoked:   false,
	}

	if err := s.repository.Create(permission); err != nil {
		return nil, "", err
	}

	return permission, token, nil
}

func (s *Service) Get(id string) (*entity.Permission, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, ErrNotFound
	}

	permission, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if permission == nil {
		return nil, ErrNotFound
	}

	return permission, nil
}

func (s *Service) GetByToken(token string) (*entity.Permission, error) {
	token = strings.TrimSpace(token)

	if token == "" {
		return nil, ErrTokenEmpty
	}

	tokenHash := credential.Hash(token)

	permission, err := s.repository.FindByToken(tokenHash)
	if err != nil {
		return nil, err
	}

	if permission == nil {
		return nil, ErrNotFound
	}

	if permission.Revoked {
		return nil, ErrRevoked
	}

	return permission, nil
}

func (s *Service) List() ([]entity.Permission, error) {
	return s.repository.FindAll()
}

func (s *Service) ChangePrivilege(id string, privilege entity.Privilege) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	permission, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if permission == nil {
		return ErrNotFound
	}

	if permission.Revoked {
		return err
	}

	permission.Privilege = privilege

	return s.repository.Update(permission)
}

func (s *Service) Revoke(id string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	permission, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if permission == nil {
		return ErrNotFound
	}

	if permission.Revoked {
		return nil
	}

	permission.Revoked = true

	return s.repository.Update(permission)
}

func (s *Service) Delete(id string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	permission, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if permission == nil {
		return ErrNotFound
	}

	return s.repository.Delete(id)
}
