package auth

import (
	"os"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
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

func (s *Service) Enroll(
	userHostname string,
	publicKey string,
	userStatus entity.UserStatus,
) (string, string, error) {
	permission, err := s.permissionService.GetByPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	_, token, err := s.userService.Create(userHostname, permission.ID, userStatus)
	if err != nil {
		return "", "", err
	}

	sotHostname, err := os.Hostname()
	if err != nil {
		return "", "", err
	}

	return sotHostname, token, nil
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
