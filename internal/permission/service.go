package permission

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
	"gorm.io/gorm"
)

var (
	ErrNotFound         = errors.New("permission not found")
	ErrNameEmpty        = errors.New("permission name is empty")
	ErrPrivilegeInvalid = errors.New("invalid privilege")
	ErrPublicKeyEmpty   = errors.New("public key is empty")
	ErrRevoked          = errors.New("permission revoked")
)

type Service struct {
	repository *repository
}

func NewService(repository *repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Create(
	name string,
	privilege entity.Privilege,
	group *entity.PermissionGroup,
	autoApprove bool,

	parentGroupID string,
) (*entity.Permission, *keyring.KeyPair, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return nil, nil, ErrNameEmpty
	}

	if !privilege.IsValid() {
		return nil, nil, ErrPrivilegeInvalid
	}

	keyPair, err := keyring.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	permission := &entity.Permission{
		Name:        name,
		Privilege:   privilege,
		Group:       *group,
		PublicKey:   keyPair.PublicKey,
		AutoApprove: autoApprove,
		Revoked:     false,
	}

	if err := s.repository.Create(permission, parentGroupID); err != nil {
		return nil, nil, err
	}

	return permission, keyPair, nil
}

func (s *Service) AdminExists() (bool, error) {
	permission, err := s.repository.FindAdmin()
	if err != nil {
		return false, err
	}

	return permission != nil, nil
}

// func (s *Service) Get(id string) (*entity.Permission, error) {
// 	id = strings.TrimSpace(id)

// 	if id == "" {
// 		return nil, ErrNotFound
// 	}

// 	permission, err := s.repository.Find(id)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if permission == nil {
// 		return nil, ErrNotFound
// 	}

// 	return permission, nil
// }

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

func (s *Service) ListWithApprovedUsers() ([]entity.Permission, error) {
	return s.repository.FindAllByUserStatus(entity.UserStatusApproved)
}

func (s *Service) ListWithPendingUsers() ([]entity.Permission, error) {
	return s.repository.FindAllByUserStatus(entity.UserStatusPending)
}

func (s *Service) DescendantPermission(
	groupID string,
) ([]entity.Permission, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, fmt.Errorf("group ID is required")
	}

	groups, err := s.repository.GetGroupDescendants(groupID)
	if err != nil {
		return nil, err
	}

	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		groupIDs = append(groupIDs, group.ID)
	}

	return s.repository.FindByGroupIDs(groupIDs)
}

func (s *Service) Update(
	updated *entity.Permission,
	parentGroupID string,
	sotID string,
) error {
	if updated == nil {
		return ErrNotFound
	}

	updated.ID = strings.TrimSpace(updated.ID)
	updated.Name = strings.TrimSpace(updated.Name)

	if updated.ID == "" {
		return ErrNotFound
	}

	if updated.Name == "" {
		return ErrNameEmpty
	}

	if !updated.Privilege.IsValid() {
		return ErrPrivilegeInvalid
	}

	permission, err := s.repository.GetPermission(
		updated.ID,
		sotID,
		false,
	)
	if err != nil {
		return err
	}

	permission.Name = updated.Name
	permission.Privilege = updated.Privilege
	permission.AutoApprove = updated.AutoApprove
	permission.Revoked = updated.Revoked
	permission.Group = updated.Group
	permission.GroupID = updated.GroupID

	return s.repository.Update(permission, parentGroupID)
}

func (s *Service) SetRevoked(id string, revoked bool) error {
	return s.repository.SetRevoked(id, revoked)
}

func (s *Service) Delete(id string, sotID string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	permission, err := s.repository.GetPermission(id, sotID, false)
	if err != nil {
		return err
	}

	if permission == nil {
		return ErrNotFound
	}

	return s.repository.Delete(id)
}

func (s *Service) GetPublicKeysByGroupIDs(
	groupIDs []string,
	sotID string,
) (map[string][]entity.Permission, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}

	if sotID == "" {
		return nil, fmt.Errorf("SOT ID is required")
	}

	permissions, err := s.repository.GetPublicKeysByGroupIDs(groupIDs, sotID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys by group IDs: %w", err)
	}

	return permissions, nil
}

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
