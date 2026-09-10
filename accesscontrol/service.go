package accesscontrol

import (
	"errors"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultaccess"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrPermission = errors.New("permission denied")
)

type Service struct {
	userService        *user.Service
	permissionService  *permission.Service
	vaultAccessService *vaultaccess.Service
	vaultService       *vault.Service
}

func NewService(
	userService *user.Service,
	permissionService *permission.Service,
	vaultAccessService *vaultaccess.Service,
	vaultService *vault.Service,
) *Service {
	return &Service{
		userService:        userService,
		permissionService:  permissionService,
		vaultAccessService: vaultAccessService,
		vaultService:       vaultService,
	}
}

func (s *Service) Get(
	authUser *entity.User,
	id string,
) (*entity.Permission, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	return s.permissionService.Get(id)
}

func (s *Service) List(
	authUser *entity.User,
) ([]entity.Permission, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	return s.permissionService.List()
}

func (s *Service) Create(
	authUser *entity.User,
	name string,
	privilege entity.Privilege,
) ([]entity.VaultAccess, *entity.Permission, *keyring.KeyPair, error) {
	if !authUser.HasAdminPermission() {
		return nil, nil, nil, ErrPermission
	}

	vaultAccessList, err := s.vaultService.VaultAccessList(authUser)
	if err != nil {
		return nil, nil, nil, err
	}

	permissionData, keyPair, err := s.permissionService.Create(name, privilege)
	if err != nil {
		return nil, nil, nil, err
	}

	return vaultAccessList, permissionData, keyPair, err
}

func (s *Service) GrantPrivilege(
	authUser *entity.User,
	vaultAccessList []entity.VaultAccess,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	_, err := s.vaultAccessService.CreateBulk(vaultAccessList)
	return err
}

func (s *Service) ChangeName(
	authUser *entity.User,
	id string,
	name string,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	return s.permissionService.ChangeName(id, name)
}

func (s *Service) ChangePrivilege(
	authUser *entity.User,
	id string,
	privilege entity.Privilege,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	if authUser.PermissionID == id {
		return ErrPermission
	}

	return s.permissionService.ChangePrivilege(id, privilege)
}

func (s *Service) Revoke(
	authUser *entity.User,
	id string,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	return s.permissionService.Revoke(id)
}

func (s *Service) UserList(
	authUser *entity.User,
	permissionId string,
) ([]entity.User, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	permission, err := s.permissionService.Get(permissionId)
	if err != nil {
		return nil, err
	}

	return permission.Users, nil
}

func (s *Service) ApproveUser(
	authUser *entity.User,
	userId string,
) (*entity.User, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	return s.userService.UpdateStatus(
		userId,
		entity.UserStatusApproved,
	)
}

func (s *Service) RevokeUser(
	authUser *entity.User,
	userId string,
) (*entity.User, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	return s.userService.UpdateStatus(
		userId,
		entity.UserStatusRevoked,
	)
}

func (s *Service) DeletePermission(
	authUser *entity.User,
	id string,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	if authUser.PermissionID == id {
		return ErrPermission
	}
	return s.permissionService.Delete(id)
}
