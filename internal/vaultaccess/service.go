package vaultaccess

import (
	"errors"
	"fmt"

	"github.com/tacenva/tacenva-core/entity"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/util/keyring"
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
	) ([]entity.AccessGroup, error)
}

func NewService(
	repository *repository,

	PublicKeyOfGroups func(
		authorizer *tacenvaentity.User,
		groupIDs []string,
	) (map[string]string, error),

	List func(
		sotID string,
	) ([]entity.AccessGroup, error),
) *Service {
	return &Service{
		repository:        repository,
		PublicKeyOfGroups: PublicKeyOfGroups,
		AllAccessGroup:    List,
	}
}

func (s *Service) Sync(
	tx *gorm.DB,
	vaultAccessList []tacpassentity.VaultAccess,
) error {
	if tx == nil {
		return errors.New("transaction is required")
	}

	if len(vaultAccessList) == 0 {
		return nil
	}

	vaultID := vaultAccessList[0].VaultID

	existing, err := s.repository.FindByVault(tx, vaultID)
	if err != nil {
		return err
	}

	incomingGroupIDs := make(map[string]struct{}, len(vaultAccessList))
	existingGroupIDs := make(map[string]struct{}, len(existing))

	for _, item := range existing {
		existingGroupIDs[item.AccessGroupID] = struct{}{}
	}

	for i := range vaultAccessList {
		item := &vaultAccessList[i]

		if item.VaultID != vaultID {
			return errors.New("all vault access records must belong to the same vault")
		}

		if item.AccessGroupID == "" {
			return errors.New("access group ID cannot be empty")
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

	if err := s.repository.DeleteBulkTx(tx, vaultID, toDelete); err != nil {
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

	return s.repository.CreateBulkTx(tx, toCreate)
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
		keyPairOfGroup := keyring.FromPublicKey(publicKeyList[groupID])
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
