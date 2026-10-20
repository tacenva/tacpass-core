package accesscontrol

import (
	"errors"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/user"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpass-core/vault"
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
	group *entity.PermissionGroup,
	autoApprove bool,
) ([]entity.VaultAccess, *entity.Permission, *keyring.KeyPair, error) {
	if !authUser.HasAdminPermission() {
		return nil, nil, nil, ErrPermission
	}

	vaultAccessList, err := s.vaultService.VaultAccessList(authUser)
	if err != nil {
		return nil, nil, nil, err
	}

	permissionData, keyPair, err := s.permissionService.Create(name, privilege, group, autoApprove)
	if err != nil {
		return nil, nil, nil, err
	}

	return vaultAccessList, permissionData, keyPair, err
}

func (s *Service) Update(
	authUser *entity.User,
	permission *entity.Permission,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	return s.permissionService.Update(permission)
}

func (s *Service) SetRevoked(
	authUser *entity.User,
	id string,
	revoked bool,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	if id == authUser.PermissionID {
		return ErrPermission
	}

	return s.permissionService.SetRevoked(id, revoked)
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

func (s *Service) ApproveUserInternal(
	userId string,
) (*entity.User, error) {
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

func (s *Service) InitAdminPrivilege(name string) (*entity.Permission, *keyring.KeyPair, error) {
	adminExists, err := s.permissionService.AdminExists()
	if err != nil {
		return nil, nil, err
	}

	if adminExists {
		return nil, nil, errors.New("admin was initialized")
	}

	return s.permissionService.Create(name, entity.PrivilegeAdmin, &entity.PermissionGroup{}, false)
}

func (s *Service) ListInternal() ([]entity.Permission, error) {
	return s.permissionService.ListWithPendingUsers()
}

func (s *Service) GetInternal(
	id string,
) (*entity.Permission, error) {
	return s.permissionService.Get(id)
}

func (s *Service) GetGroups(
	authUser *entity.User,
) ([]entity.PermissionGroup, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	return s.permissionService.GetGroups()
}

func (s *Service) UpdateGroup(
	authUser *entity.User,
	group *entity.PermissionGroup,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	return s.permissionService.UpdateGroup(group)
}

func (s *Service) DeleteGroup(
	authUser *entity.User,
	groupID string,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	return s.permissionService.DeleteGroup(groupID)
}
