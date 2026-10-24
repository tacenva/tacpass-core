package permission

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

func (s *Service) GetGroupDescendants(groupID string) ([]entity.PermissionGroup, error) {
	return s.repository.GetGroupDescendants(groupID)
}

func (s *Service) UpdateGroup(group *entity.PermissionGroup) error {
	return s.repository.UpdateGroup(group)
}

func (s *Service) DeleteGroup(groupID string) error {
	return s.repository.DeleteGroup(groupID)
}

func (s *Service) HasGroupPermission(
	referenceGroupID string,
	candidateGroupID string,
	sotID string,
) (bool, error) {
	referenceGroupID = strings.TrimSpace(referenceGroupID)
	candidateGroupID = strings.TrimSpace(candidateGroupID)
	sotID = strings.TrimSpace(sotID)

	if referenceGroupID == "" ||
		candidateGroupID == "" ||
		sotID == "" {
		return false, fmt.Errorf(
			"reference group ID, candidate group ID, and SOT ID are required",
		)
	}

	return s.repository.IsSameOrDescendantGroup(
		referenceGroupID,
		candidateGroupID,
		sotID,
	)
}

func (s *Service) GetPermission(permissionID string, sotID string, withBool bool) (*entity.Permission, error) {
	permissionID = strings.TrimSpace(permissionID)
	sotID = strings.TrimSpace(sotID)
	if permissionID == "" || sotID == "" {
		return nil, errors.New("required value")
	}

	return s.repository.GetPermission(permissionID, sotID, withBool)
}

func (s *Service) GetPermissionByUserID(userID string) (*entity.Permission, error) {
	return s.repository.FindPermissionByUserID(userID)
}

func (s *Service) GroupList(sotID string) ([]entity.PermissionGroup, error) {
	return s.repository.FindGroupBySotID(sotID)
}

func (s *Service) SyncGroups(
	sotID string,
	incomingGroups []entity.PermissionGroup,
) error {
	incomingIDs := make([]string, 0, len(incomingGroups))
	seen := make(map[string]struct{}, len(incomingGroups))

	for i := range incomingGroups {
		id := incomingGroups[i].ID

		if id == "" {
			return fmt.Errorf("group ID cannot be empty")
		}

		if _, exists := seen[id]; exists {
			return fmt.Errorf("duplicate group ID: %s", id)
		}

		seen[id] = struct{}{}
		incomingIDs = append(incomingIDs, id)
		incomingGroups[i].SotID = sotID
	}

	return s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Upsert(tx, sotID, incomingGroups); err != nil {
			return err
		}

		if err := s.repository.DeleteMissing(tx, sotID, incomingIDs); err != nil {
			return err
		}

		return nil
	})
}
