package accesscontrol

import (
	"errors"

	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/user"
	"github.com/tacenva/tacpass-core/util/keyring"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrPermission = errors.New("permission denied")
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

func (s *Service) List(
	authUser *entity.User,
) ([]entity.Permission, error) {
	if !authUser.HasAdminPermission() {
		return nil, ErrPermission
	}

	return s.permissionService.DescendantPermission(authUser.Permission.GroupID)
}

func (s *Service) Create(
	authUser *entity.User,
	name string,
	privilege entity.Privilege,
	group *entity.PermissionGroup,
	autoApprove bool,
	sotID string,
) (*entity.Permission, *keyring.KeyPair, error) {
	if !authUser.HasAdminPermission() {
		return nil, nil, ErrPermission
	}

	group.SotID = sotID

	permissionData, keyPair, err := s.permissionService.Create(name, privilege, group, autoApprove, authUser.Permission.GroupID)
	if err != nil {
		return nil, nil, err
	}

	return permissionData, keyPair, err
}

func (s *Service) Update(
	authUser *entity.User,
	permission *entity.Permission,
	sotID string,
) error {
	if err := s.hasGroupPermission(
		authUser,
		permission.GroupID, // groupid preupdate
		sotID,
	); err != nil {
		return err
	}

	return s.permissionService.Update(permission, authUser.Permission.GroupID, sotID)
}

func (s *Service) SetRevoked(
	authUser *entity.User,
	permissionId string,
	sotID string,
	revoked bool,
) error {
	permission, err := s.permissionService.GetPermission(permissionId, sotID, true)
	if err != nil {
		return err
	}

	if err := s.hasGroupPermission(
		authUser,
		permission.GroupID,
		sotID,
	); err != nil {
		return err
	}

	if permission.ID == authUser.PermissionID {
		return ErrPermission
	}

	return s.permissionService.SetRevoked(permission.ID, revoked)
}

func (s *Service) UserList(
	authUser *entity.User,
	permissionId string,
	sotID string,
) ([]entity.User, error) {
	permission, err := s.permissionService.GetPermission(permissionId, sotID, true)
	if err != nil {
		return nil, err
	}

	if err := s.hasGroupPermission(
		authUser,
		permission.GroupID,
		sotID,
	); err != nil {
		return nil, err
	}

	return permission.Users, nil
}

func (s *Service) ApproveUser(
	authUser *entity.User,
	userId string,
	sotID string,
) (*entity.User, error) {
	permission, err := s.permissionService.GetPermissionByUserID(userId)
	if err != nil {
		return nil, err
	}

	if err := s.hasGroupPermission(
		authUser,
		permission.GroupID,
		sotID,
	); err != nil {
		return nil, err
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
	sotID string,
) (*entity.User, error) {
	permission, err := s.permissionService.GetPermissionByUserID(userId)
	if err != nil {
		return nil, err
	}

	if err := s.hasGroupPermission(
		authUser,
		permission.GroupID,
		sotID,
	); err != nil {
		return nil, err
	}

	return s.userService.UpdateStatus(
		userId,
		entity.UserStatusRevoked,
	)
}

func (s *Service) DeletePermission(
	authUser *entity.User,
	id string,
	sotID string,
) error {
	permission, err := s.permissionService.GetPermission(id, sotID, false)
	if err != nil {
		return err
	}

	if err := s.hasGroupPermission(
		authUser,
		permission.GroupID,
		sotID,
	); err != nil {
		return err
	}

	if authUser.PermissionID == id {
		return ErrPermission
	}

	return s.permissionService.Delete(id, sotID)
}

func (s *Service) InitAdminPrivilege(name string, sotID string) (*entity.Permission, *keyring.KeyPair, error) {
	adminExists, err := s.permissionService.AdminExists()
	if err != nil {
		return nil, nil, err
	}

	if adminExists {
		return nil, nil, errors.New("admin was initialized")
	}

	return s.permissionService.Create(name, entity.PrivilegeAdmin, &entity.PermissionGroup{
		Name:  "Tacenva Admin",
		SotID: sotID,
	}, false, "")
}

func (s *Service) ListInternal() ([]entity.Permission, error) {
	return s.permissionService.ListWithPendingUsers()
}

func (s *Service) GetInternal(
	id string,
	sotID string,
) (*entity.Permission, error) {
	return s.permissionService.GetPermission(id, sotID, true)
}

func (s *Service) GetGroupDescendants(
	authUser *entity.User,
) (*contract.GroupAssignment, error) {
	if !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	groupID := authUser.Permission.GroupID
	groups, err := s.permissionService.GetGroupDescendants(groupID)
	if err != nil {
		return nil, err
	}
	return &contract.GroupAssignment{
		ID:    groupID,
		Items: groups,
	}, nil
}

func (s *Service) UpdateGroup(
	authUser *entity.User,
	group *entity.PermissionGroup,
	sotID string,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	if err := s.hasGroupPermission(
		authUser,
		group.ID,
		sotID,
	); err != nil {
		return err
	}

	return s.permissionService.UpdateGroup(group)
}

func (s *Service) DeleteGroup(
	authUser *entity.User,
	groupID string,
	sotID string,
) error {
	if err := s.hasGroupPermission(
		authUser,
		groupID,
		sotID,
	); err != nil {
		return err
	}

	return s.permissionService.DeleteGroup(groupID)
}

func (s *Service) hasGroupPermission(
	authUser *entity.User,
	groupID string,
	sotID string,
) error {
	if !authUser.HasAdminPermission() {
		return ErrPermission
	}

	accessible, err := s.permissionService.HasGroupPermission(
		authUser.Permission.GroupID,
		groupID,
		sotID,
	)
	if err != nil {
		return err
	}

	if !accessible {
		return ErrPermission
	}

	return nil
}

func (s *Service) GroupList(sotID string) ([]entity.PermissionGroup, error) {
	return s.permissionService.GroupList(sotID)
}

func (s *Service) SyncGroups(sotID string, groups []entity.PermissionGroup) error {
	return s.permissionService.SyncGroups(sotID, groups)
}
