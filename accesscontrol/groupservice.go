package accesscontrol

import "github.com/tacenva/tacpass-core/entity"

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

func (s *Service) GroupList(sotID string) ([]entity.PermissionGroup, error) {
	return s.permissionService.GroupList(sotID)
}

func (s *Service) SyncGroups(sotID string, groups []entity.PermissionGroup) error {
	return s.permissionService.SyncGroups(sotID, groups)
}
