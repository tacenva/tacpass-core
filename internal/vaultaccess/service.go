package vaultaccess

import (
	"errors"
	"fmt"

	tacpassentity "github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type Service struct {
	repository *repository
}

func NewService(repository *repository) *Service {
	return &Service{
		repository: repository,
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

func (s *Service) List(
	vaultID string,
	accessGroupID string,
) (*tacpassentity.VaultAccess, error) {
	return s.repository.FindByVaultAndAccessGroup(
		vaultID,
		accessGroupID,
	)
}

// func validateVaultAccess(
// 	vaultAccess *entity.VaultAccess,
// 	requireID bool,
// ) error {
// 	if requireID && strings.TrimSpace(vaultAccess.ID) == "" {
// 		return fmt.Errorf("%w: ID", errormessage.ErrEmptyField)
// 	}

// 	vaultAccess.ID = strings.TrimSpace(vaultAccess.ID)
// 	vaultAccess.VaultID = strings.TrimSpace(vaultAccess.VaultID)
// 	vaultAccess.AccessGroupID = strings.TrimSpace(vaultAccess.AccessGroupID)
// 	vaultAccess.WrappedVaultKey = strings.TrimSpace(vaultAccess.WrappedVaultKey)

// 	if vaultAccess.VaultID == "" {
// 		return fmt.Errorf("%w: VaultID", errormessage.ErrEmptyField)
// 	}

// 	if vaultAccess.AccessGroupID == "" {
// 		return fmt.Errorf("%w: AccessGroupID", errormessage.ErrEmptyField)
// 	}

// 	if vaultAccess.WrappedVaultKey == "" {
// 		return fmt.Errorf("%w: WrappedVaultKey", errormessage.ErrEmptyField)
// 	}

// 	return nil
// }

// func (s *Service) CreateBulk(
// 	values []entity.VaultAccess,
// ) ([]entity.VaultAccess, error) {
// 	if len(values) == 0 {
// 		return values, nil
// 	}

// 	vaultAccesses := make([]*entity.VaultAccess, len(values))

// 	for i := range values {
// 		if err := validateVaultAccess(&values[i], false); err != nil {
// 			return nil, err
// 		}

// 		vaultAccesses[i] = &values[i]
// 	}

// 	if err := s.repository.CreateBulk(vaultAccesses); err != nil {
// 		return nil, err
// 	}

// 	return values, nil
// }

// func (s *Service) CreateBulkTx(
// 	tx *gorm.DB,
// 	values []entity.VaultAccess,
// ) ([]entity.VaultAccess, error) {
// 	if tx == nil {
// 		return nil, errors.New("transaction is required")
// 	}

// 	if len(values) == 0 {
// 		return values, nil
// 	}

// 	vaultAccesses := make([]*entity.VaultAccess, len(values))

// 	for i := range values {
// 		if err := validateVaultAccess(&values[i], false); err != nil {
// 			return nil, err
// 		}

// 		vaultAccesses[i] = &values[i]
// 	}

// 	if err := s.repository.CreateBulkTx(
// 		tx,
// 		vaultAccesses,
// 	); err != nil {
// 		return nil, err
// 	}

// 	return values, nil
// }

// func (s *Service) Sync(
// 	tx *gorm.DB,
// 	vaultID string,
// 	incomingVaultAccesses []entity.VaultAccess,
// ) error {
// 	if len(incomingVaultAccesses) == 0 {
// 		return nil
// 	}

// 	incomingIDs := make([]string, 0, len(incomingVaultAccesses))
// 	seen := make(map[string]struct{}, len(incomingVaultAccesses))

// 	for i := range incomingVaultAccesses {
// 		id := incomingVaultAccesses[i].ID

// 		if id == "" {
// 			return fmt.Errorf("group ID cannot be empty")
// 		}

// 		if _, exists := seen[id]; exists {
// 			return fmt.Errorf("duplicate group ID: %s", id)
// 		}

// 		seen[id] = struct{}{}
// 		incomingIDs = append(incomingIDs, id)
// 	}

// 	return s.repository.Transaction(func(tx *gorm.DB) error {
// 		if err := s.repository.Upsert(tx, incomingVaultAccesses); err != nil {
// 			return err
// 		}

// 		if err := s.repository.DeleteMissing(tx, incomingIDs); err != nil {
// 			return err
// 		}

// 		return nil
// 	})
// }

// func (s *Service) IsVaultAccesible(
// 	vaultID string,
// 	permissionID string,
// ) (bool, error) {
// 	vaultAccess, err := s.repository.FindByVaultAndPermission(
// 		vaultID,
// 		permissionID,
// 	)
// 	if err != nil {
// 		return false, err
// 	}

// 	if vaultAccess == nil {
// 		return false, nil
// 	}

// 	return true, nil
// }

// func (s *Service) List() ([]entity.VaultAccess, error) {
// 	return s.repository.FindAll()
// }

// func (s *Service) Delete(id string) error {
// 	id = strings.TrimSpace(id)

// 	if id == "" {
// 		return fmt.Errorf("%w: ID", errormessage.ErrEmptyField)
// 	}

// 	return s.repository.Delete(id)
// }

// func (s *Service) DeleteBulkTx(
// 	tx *gorm.DB,
// 	values []entity.VaultAccess,
// ) error {
// 	if tx == nil {
// 		return errors.New("transaction is required")
// 	}

// 	if len(values) == 0 {
// 		return nil
// 	}

// 	vaultAccesses := make([]*entity.VaultAccess, len(values))

// 	for i := range values {
// 		if err := validateVaultAccess(&values[i], false); err != nil {
// 			return err
// 		}

// 		vaultAccesses[i] = &values[i]
// 	}

// 	if err := s.repository.DeleteBulkTx(
// 		tx,
// 		vaultAccesses,
// 	); err != nil {
// 		return err
// 	}

// 	return nil
// }

// func (s *Service) DeleteBulkByGroupIDsTx(
// 	tx *gorm.DB,
// 	groupIDS []string,
// ) error {
// 	return s.repository.DeleteBulkByGroupIDsTx(
// 		tx,
// 		groupIDS,
// 	)
// }

// func (s *Service) FindByVaultID(
// 	vaultID string,
// ) ([]entity.VaultAccess, error) {
// 	vaultID = strings.TrimSpace(vaultID)

// 	if vaultID == "" {
// 		return nil, fmt.Errorf("%w: vaultID", errormessage.ErrEmptyField)
// 	}

// 	return s.repository.FindByVaultID(
// 		vaultID,
// 	)
// }

// func (s *Service) FindByVaultAndAccess(
// 	vaultID string,
// 	permissionID string,
// ) (*entity.VaultAccess, error) {
// 	vaultID = strings.TrimSpace(vaultID)

// 	if vaultID == "" {
// 		return nil, fmt.Errorf("%w: vaultID", errormessage.ErrEmptyField)
// 	}

// 	return s.repository.FindByVaultAndAccess(
// 		vaultID,
// 		permissionID,
// 	)
// }
