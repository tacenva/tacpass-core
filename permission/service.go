package permission

import (
	"errors"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

var (
	ErrNotFound         = errors.New("permission not found")
	ErrPrivilegeInvalid = errors.New("invalid privilege")
	ErrPublicKeyEmpty   = errors.New("public key is empty")
	ErrRevoked          = errors.New("permission revoked")
)

// const accessTokenSize = 32

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
) (*entity.Permission, *keyring.KeyPair, error) {
	if !privilege.IsValid() {
		return nil, nil, ErrPrivilegeInvalid
	}

	keyPair, err := keyring.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	permission := &entity.Permission{
		Privilege: privilege,
		PublicKey: keyPair.PublicKey,
		// AccessToken: credential.Hash(accessToken),
		Revoked: false,
	}

	if err := s.repository.Create(permission); err != nil {
		return nil, nil, err
	}

	return permission, keyPair, nil
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

// func (s *Service) GetByToken(accessToken string) (*entity.Permission, error) {
// 	accessToken = strings.TrimSpace(accessToken)

// 	if accessToken == "" {
// 		return nil, ErrTokenEmpty
// 	}

// 	accessTokenHash := credential.Hash(accessToken)

// 	permission, err := s.repository.FindByToken(accessTokenHash)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if permission == nil {
// 		return nil, ErrNotFound
// 	}

// 	if permission.Revoked {
// 		return nil, ErrRevoked
// 	}

// 	return permission, nil
// }

func (s *Service) List() ([]entity.Permission, error) {
	return s.repository.FindAll()
}

func (s *Service) VaultList(permissionId string) ([]entity.VaultAccess, error) {
	return s.repository.GetVault(permissionId)
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
