package vaultrecord

import (
	"errors"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/sync"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
)

var (
	ErrForbidden       = errors.New("forbidden")
	ErrVaultIDEmpty    = errors.New("vault ID cannot be empty")
	ErrRecordIDEmpty   = errors.New("record ID cannot be empty")
	ErrRecordDataEmpty = errors.New("record data cannot be empty")
)

const syncEntityVaultRecord = "vault_record"

type Service struct {
	tacenvaDB          *database.DB
	syncService        *sync.Service
	vaultaccessService *vaultaccess.Service
}

func NewService(
	tacenvaDB *database.DB,
	syncService *sync.Service,
	vaultaccessService *vaultaccess.Service,
) *Service {
	return &Service{
		tacenvaDB:          tacenvaDB,
		syncService:        syncService,
		vaultaccessService: vaultaccessService,
	}
}

func (s *Service) List(
	vaultKey string,
	vaultID string,
) ([]entity.VaultRecord, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	fileDB, err := s.tacenvaDB.File(
		vaultID,
		string(vaultKey),
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return nil, err
	}

	var records []entity.VaultRecord
	err = fileDB.FindAll(&records)
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (s *Service) Create(
	vaultKey string,
	vaultID string,
	record *entity.VaultRecord,
) (string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return "", ErrVaultIDEmpty
	}

	if record == nil {
		return "", ErrRecordDataEmpty
	}

	userIDs, err := s.userIDsByVaultID(vaultID)
	if err != nil {
		return "", err
	}

	fileDB, err := s.tacenvaDB.File(
		vaultID,
		string(vaultKey),
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return "", err
	}

	recordID, err := fileDB.Insert(record)
	if err != nil {
		return "", err
	}

	if err := s.syncService.RecordChange(
		nil,
		s.getEntityName(vaultID),
		recordID,
		sync.OperationCreate,
		userIDs,
	); err != nil {
		return "", err
	}

	return recordID, nil
}

func (s *Service) Update(
	vaultKey string,
	vaultID string,
	record *entity.VaultRecord,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if record == nil {
		return ErrRecordDataEmpty
	}

	if record.ID == "" {
		return ErrRecordIDEmpty
	}

	userIDs, err := s.userIDsByVaultID(vaultID)
	if err != nil {
		return err
	}

	fileDB, err := s.tacenvaDB.File(
		vaultID,
		string(vaultKey),
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return err
	}

	if err := fileDB.Update(record); err != nil {
		return err
	}

	return s.syncService.RecordChange(
		nil,
		s.getEntityName(vaultID),
		record.ID,
		sync.OperationUpdate,
		userIDs,
	)
}

func (s *Service) Delete(
	vaultKey string,
	vaultID string,
	recordID string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if recordID == "" {
		return ErrRecordIDEmpty
	}

	userIDs, err := s.userIDsByVaultID(vaultID)
	if err != nil {
		return err
	}

	fileDB, err := s.tacenvaDB.File(
		vaultID,
		string(vaultKey),
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return err
	}

	_, err = fileDB.Delete(recordID)
	if err != nil {
		return err
	}

	return s.syncService.RecordChange(
		nil,
		s.getEntityName(vaultID),
		recordID,
		sync.OperationDelete,
		userIDs,
	)
}

func (s *Service) userIDsByVaultID(
	vaultID string,
) ([]string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	vaultAccessList, err := s.vaultaccessService.FindByVaultID(
		vaultID,
	)
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, 0)
	seen := make(map[string]struct{})

	for _, vaultAccess := range vaultAccessList {
		for _, user := range vaultAccess.Permission.Users {
			if user.ID == "" {
				continue
			}

			if _, ok := seen[user.ID]; ok {
				continue
			}

			seen[user.ID] = struct{}{}

			userIDs = append(
				userIDs,
				user.ID,
			)
		}
	}

	return userIDs, nil
}

func (s *Service) getEntityName(vaultID string) string {
	return syncEntityVaultRecord + ":" + vaultID
}
