package permission

import (
	"errors"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

var (
	ErrNotFound         = errors.New("permission not found")
	ErrNameEmpty        = errors.New("permission name is empty")
	ErrPrivilegeInvalid = errors.New("invalid privilege")
	ErrPublicKeyEmpty   = errors.New("public key is empty")
	ErrRevoked          = errors.New("permission revoked")
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
	name string,
	privilege entity.Privilege,
) (*entity.Permission, *keyring.KeyPair, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return nil, nil, ErrNameEmpty
	}

	if !privilege.IsValid() {
		return nil, nil, ErrPrivilegeInvalid
	}

	keyPair, err := keyring.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	permission := &entity.Permission{
		Name:      name,
		Privilege: privilege,
		PublicKey: keyPair.PublicKey,
		Revoked:   false,
	}

	if err := s.repository.Create(permission); err != nil {
		return nil, nil, err
	}

	return permission, keyPair, nil
}

func (s *Service) AdminExists() (bool, error) {
	permission, err := s.repository.FindAdmin()
	if err != nil {
		return false, err
	}

	return permission != nil, nil
}

func (s *Service) Get(id string) (*entity.Permission, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, ErrNotFound
	}

	permission, err := s.repository.Find(id)
	if err != nil {
		return nil, err
	}

	if permission == nil {
		return nil, ErrNotFound
	}

	return permission, nil
}

func (s *Service) GetByPublicKey(publicKey string) (*entity.Permission, error) {
	publicKey = strings.TrimSpace(publicKey)

	if publicKey == "" {
		return nil, ErrPublicKeyEmpty
	}

	permission, err := s.repository.FindByPublicKey(publicKey)
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

func (s *Service) ChangeName(id string, name string) error {
	name = strings.TrimSpace(name)

	if name == "" {
		return ErrNameEmpty
	}

	permission, err := s.repository.Find(id)
	if err != nil {
		return err
	}

	if permission.Revoked {
		return ErrRevoked
	}

	permission.Name = name
	return s.repository.Update(permission)
}

func (s *Service) ChangePrivilege(
	id string,
	privilege entity.Privilege,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	if !privilege.IsValid() {
		return ErrPrivilegeInvalid
	}

	permission, err := s.repository.Find(id)
	if err != nil {
		return err
	}

	if permission == nil {
		return ErrNotFound
	}

	if permission.Revoked {
		return ErrRevoked
	}

	permission.Privilege = privilege

	return s.repository.Update(permission)
}

func (s *Service) Revoke(id string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	permission, err := s.repository.Find(id)
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

	permission, err := s.repository.Find(id)
	if err != nil {
		return err
	}

	if permission == nil {
		return ErrNotFound
	}

	return s.repository.Delete(id)
}
