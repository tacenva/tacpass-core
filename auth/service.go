package auth

import (
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	"github.com/tacenva/tacpass-core/util/keyring"
)

type Service struct {
	userService       *user.Service
	permissionService *permission.Service
}

func NewService(
	userService *user.Service,
	permissionService *permission.Service,
) *Service {
	return &Service{
		userService:       userService,
		permissionService: permissionService,
	}
}

func (s *Service) RequestEnrollment(
	hostname string,
	publicKey string,
	userStatus entity.UserStatus,
) (string, error) {
	permission, err := s.permissionService.GetByPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	_, token, err := s.userService.Create(hostname, permission.ID, userStatus)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Service) Initialize(hostname string) (string, *keyring.KeyPair, error) {
	_, keyPair, err := s.permissionService.Create(entity.PrivilegeAdmin)
	if err != nil {
		return "", nil, err
	}

	token, err := s.RequestEnrollment(
		hostname,
		keyPair.PublicKey,
		entity.UserStatusApproved,
	)

	return token, keyPair, err
}

func (s *Service) GetStatus(token string) error {
	userData, err := s.userService.GetByToken(token)
	if err != nil {
		return err
	}

	if userData.Permission.Revoked {
		return permission.ErrRevoked
	}

	switch userData.Status {
	case entity.UserStatusApproved:
		return nil

	case entity.UserStatusPending:
		return user.ErrPending

	case entity.UserStatusRevoked:
		return user.ErrRevoked

	default:
		return user.ErrStatusInvalid
	}
}

func (s *Service) GetPermission(authToken string) (*entity.Permission, error) {
	userData, err := s.userService.GetByToken(authToken)
	if err != nil {
		return nil, err
	}

	return &userData.Permission, nil
}

func (s *Service) GetUserData(token string) (*entity.User, error) {
	userData, err := s.userService.GetByToken(token)
	if err != nil {
		return nil, err
	}

	if userData.Permission.Revoked {
		return nil, permission.ErrRevoked
	}

	switch userData.Status {
	case entity.UserStatusApproved:
		return userData, nil

	case entity.UserStatusPending:
		return nil, user.ErrPending

	case entity.UserStatusRevoked:
		return nil, user.ErrRevoked

	default:
		return nil, user.ErrStatusInvalid
	}
}
