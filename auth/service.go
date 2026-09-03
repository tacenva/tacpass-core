package auth

import (
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

func (s *Service) Access(
	hostname string,
	permissionToken string,
	userStatus entity.UserStatus,
) (string, error) {
	permission, err := s.permissionService.GetByToken(permissionToken)
	if err != nil {
		return "", err
	}

	_, token, err := s.userService.Create(hostname, permission.ID, userStatus)
	if err != nil {
		return "", err
	}

	return token, nil
}
