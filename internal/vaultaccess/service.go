package vaultaccess

import (
	"fmt"
	"strings"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/genericerror"
	"github.com/tacenva/tacenva-core/util/keyring"
	"github.com/tacenva/tacpass-core/contract"
	tacpassentity "github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type Service struct {
	repository *repository

	PublicKeyOfGroups func(
		authorizer *tacenvaentity.User,
		groupIDs []string,
	) (map[string]string, error)

	AllAccessGroup func(
		sotID string,
	) ([]tacenvaentity.AccessGroup, error)

	SyncGroups func(
		sotID string,
		groups []tacenvaentity.AccessGroup,
		lastSyncChange *tacenvaentity.SyncChange,
	) error
}

func NewService(
	repository *repository,

	PublicKeyOfGroups func(
		authorizer *tacenvaentity.User,
		groupIDs []string,
	) (map[string]string, error),

	AllAccessGroup func(
		sotID string,
	) ([]tacenvaentity.AccessGroup, error),

	SyncGroups func(
		sotID string,
		groups []tacenvaentity.AccessGroup,
		lastSyncChange *tacenvaentity.SyncChange,
	) error,
) *Service {
	return &Service{
		repository:        repository,
		PublicKeyOfGroups: PublicKeyOfGroups,
		AllAccessGroup:    AllAccessGroup,
		SyncGroups:        SyncGroups,
	}
}

func (s *Service) Sync(
	tx *gorm.DB,
	vaultID string,
	vaultAccessList []tacpassentity.VaultAccess,
) error {
	if err := genericerror.ValidateRequired(map[string]any{
		"transaction": tx,
		"vault id":    vaultID,
	}); err != nil {
		return err
	}

	for i := range vaultAccessList {
		vaultAccessList[i].VaultID = vaultID
	}

	existing, err := s.repository.FindByVault(tx, vaultID)
	if err != nil {
		return err
	}

	incomingGroupIDs := make(map[string]struct{}, len(vaultAccessList))
	existingGroupIDs := make(map[string]struct{}, len(existing))

	for _, item := range existing {
		existingGroupIDs[item.AccessGroupID] = struct{}{}
	}

	for _, item := range vaultAccessList {
		if item.AccessGroupID == "" {
			continue
		}

		if _, exists := incomingGroupIDs[item.AccessGroupID]; exists {
			return fmt.Errorf("duplicate access group ID: %s", item.AccessGroupID)
		}

		incomingGroupIDs[item.AccessGroupID] = struct{}{}
	}

	var toDelete []string
	for groupID := range existingGroupIDs {
		if _, exists := incomingGroupIDs[groupID]; !exists {
			toDelete = append(toDelete, groupID)
		}
	}

	if err := s.repository.DeleteBulk(tx, vaultID, toDelete); err != nil {
		return err
	}

	toCreate := make([]tacpassentity.VaultAccess, 0, len(vaultAccessList))

	for _, item := range vaultAccessList {
		if _, exists := existingGroupIDs[item.AccessGroupID]; exists {
			continue
		}

		toCreate = append(toCreate, item)
	}

	if len(toCreate) == 0 {
		return nil
	}

	return s.repository.CreateBulk(tx, toCreate)
}

func (s *Service) Get(
	vaultID string,
	accessGroupID string,
) (*tacpassentity.VaultAccess, error) {
	return s.repository.FindByVaultAndAccessGroup(
		vaultID,
		accessGroupID,
	)
}

func (s *Service) Generate(
	publicKeyList map[string]string,
	unwrappedVaultKey []byte,
) ([]tacpassentity.VaultAccess, error) {
	vaultAccessList := make([]tacpassentity.VaultAccess, 0, len(publicKeyList))
	for groupID := range publicKeyList {
		publicKeyOfGroup := publicKeyList[groupID]
		keyPairOfGroup := keyring.FromPublicKey(publicKeyOfGroup)
		wrappedVaultKey, err := keyPairOfGroup.Seal(unwrappedVaultKey)
		if err != nil {
			return nil, err
		}

		vaultAccessList = append(vaultAccessList, tacpassentity.VaultAccess{
			AccessGroupID:   groupID,
			WrappedVaultKey: wrappedVaultKey,
		})
	}

	return vaultAccessList, nil
}

func (s *Service) Exists(
	vaultID string,
	accessGroupID string,
) (bool, error) {
	vaultID = strings.TrimSpace(vaultID)
	accessGroupID = strings.TrimSpace(accessGroupID)

	if err := genericerror.ValidateRequired(map[string]any{
		"vault id":        vaultID,
		"access group id": accessGroupID,
	}); err != nil {
		return false, err
	}

	return s.repository.Exists(vaultID, accessGroupID)
}

func (s *Service) CountAccessibleVaults(
	vaultIDs []string,
	accessGroupID string,
) (int64, error) {
	accessGroupID = strings.TrimSpace(accessGroupID)
	if accessGroupID == "" {
		return 0, genericerror.ErrRequired("access group id")
	}

	normalizedIDs := normalizeVaultIDs(vaultIDs)
	if len(normalizedIDs) == 0 {
		return 0, nil
	}

	return s.repository.CountAccessibleVaults(
		normalizedIDs,
		accessGroupID,
	)
}

func (s *Service) FindVaultChangeData(
	vaultIDs []string,
	accessGroupID string,
) (map[contract.VaultID]contract.VaultChangeData, error) {
	accessGroupID = strings.TrimSpace(accessGroupID)
	if accessGroupID == "" {
		return nil, genericerror.ErrRequired("access group id")
	}

	normalizedIDs := normalizeVaultIDs(vaultIDs)
	if len(normalizedIDs) == 0 {
		return nil, nil
	}

	return s.repository.FindVaultChangeData(
		normalizedIDs,
		accessGroupID,
	)
}

func normalizeVaultIDs(vaultIDs []string) []string {
	if len(vaultIDs) == 0 {
		return nil
	}

	normalizedIDs := make([]string, 0, len(vaultIDs))
	seen := make(map[string]struct{}, len(vaultIDs))

	for _, id := range vaultIDs {
		id = strings.TrimSpace(id)

		if id == "" {
			continue
		}

		if _, exists := seen[id]; exists {
			continue
		}

		seen[id] = struct{}{}
		normalizedIDs = append(normalizedIDs, id)
	}

	return normalizedIDs
}
