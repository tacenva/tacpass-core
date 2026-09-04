package accesscontrol

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

func (s *Service) List() ([]entity.Permission, error) {
	return s.permissionService.List()
}

func (s *Service) Create(privilege entity.Privilege) (*entity.Permission, *keyring.KeyPair, error) {
	return s.permissionService.Create(privilege)
}

func (s *Service) ChangePrivilege(id string, privilege entity.Privilege) error {
	return s.permissionService.ChangePrivilege(id, privilege)
}

func (s *Service) Revoke(id string) error {
	return s.permissionService.Revoke(id)
}

func (s *Service) UserList(permissionId string) ([]entity.User, error) {
	permission, err := s.permissionService.Get(permissionId)
	if err != nil {
		return nil, err
	}

	return permission.Users, nil
}

func (s *Service) ApproveUser(userId string) (*entity.User, error) {
	return s.userService.UpdateStatus(userId, entity.UserStatusApproved)
}

func (s *Service) RevokeUser(userId string) (*entity.User, error) {
	return s.userService.UpdateStatus(userId, entity.UserStatusRevoked)
}
