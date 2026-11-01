package vaultrecord

import (
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacpass-core/contract"
)

type Remote struct {
	syncService *sync.Service
	repository  *repository

	vaultDir        string
	vaultRecordFile *database.DatabaseFile
	sotID           *string
}

func NewRemoteService(
	syncService *sync.Service,
	repository *repository,
) *Remote {
	return &Remote{
		syncService: syncService,
		repository:  repository,
	}
}

func (s *Remote) SetConfig(
	vaultDir string,
	sotID string,
) {
	s.vaultDir = vaultDir
	s.sotID = &sotID
}

func (s *Remote) GetBlob(
	authorizer *tacenvaentity.User,
	vaultID string,
	sotID string,
) ([]byte, error) {
	if !authorizer.IsApproved() {
		return nil, ErrForbidden
	}

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	db := database.New(s.vaultDir)

	blob, err := db.ReadMetadataOnly(vaultID)
	if err != nil {
		return nil, err
	}

	return blob, nil
}

func (s *Remote) StoreBlob(
	authorizer *tacenvaentity.User,
	vaultID string,
	sotID string,
	data []byte,
) error {
	if !authorizer.HasWriteAccess() {
		return ErrForbidden
	}

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(s.vaultDir)

	err := db.Write(vaultID, data)
	if err != nil {
		return err
	}

	return nil
}

func (s *Remote) GetChangesAfter(
	vaultID string,
	startID string,
	limit int,
) (*contract.PendingVaultRecordChange, error) {
	return s.repository.GetChangesAfter(
		s.vaultDir,
		vaultID,
		*s.sotID,
		startID,
		limit,
	)
}

func (s *Remote) SyncOnSot(
	authorizer *tacenvaentity.User,
	vaultID string,
	sotStartChangeID string,
	limit int,
	replicaChanges *contract.PendingVaultRecordChange,
) (err error) {
	return s.repository.SyncOnSot(
		authorizer,
		s.vaultDir,
		*s.sotID,
		vaultID,
		sotStartChangeID,
		limit,
		replicaChanges,
	)
}

func (s *Remote) GetChangeCount(
	vaultID string,
	startID string,
) (int64, error) {
	return s.syncService.GetChangeCount(
		*s.sotID,
		s.repository.getEntityName(vaultID),
		startID,
	)
}

func (s *Remote) GetSyncLatestChangeId(
	vaultID string,
) (string, error) {
	syncState, err := s.syncService.GetSyncState(
		*s.sotID,
		s.repository.getEntityName(vaultID),
	)

	return syncState.LastChangeID, err
}
