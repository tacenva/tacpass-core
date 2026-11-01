package vaultrecord

import (
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacpass-core/contract"
	tacpassentity "github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type Local struct {
	syncService *sync.Service
	repository  *repository

	currentVaultDir    string
	vaultID            *string
	vaultRawRecordFile *database.DatabaseFile
	vaultRecordFile    *database.DatabaseFile
	entityName         *string
	sotID              *string
}

func NewLocalService(
	syncService *sync.Service,
	repository *repository,
) *Local {
	return &Local{
		syncService: syncService,
		repository:  repository,
	}
}

func (s *Local) SetConfig(
	vaultDir string,
	sotID string,
	vaultID string,
	unwrappedVaultKey string,
) error {
	s.currentVaultDir = vaultDir
	s.vaultID = &vaultID

	db := database.New(s.currentVaultDir)
	vaultRawRecordFile, err := db.NewRawFile(
		vaultID,
	)
	if err != nil {
		return err
	}
	s.vaultRawRecordFile = vaultRawRecordFile

	vaultRecordFile, err := db.File(
		vaultID,
		unwrappedVaultKey,
		database.FileModeOpen,
	)
	if err != nil {
		return err
	}
	s.vaultRecordFile = vaultRecordFile

	s.entityName = new(string)
	*s.entityName = syncEntityVaultRecord + ":" + vaultID

	s.sotID = &sotID
	return nil
}

func (s *Local) SimulateEncryption(
	record *tacpassentity.VaultRecord,
) (string, error) {
	return s.vaultRecordFile.SimulateEncryption(record)
}

func (s *Local) Init(
	vaultDir string,
	vaultID string,
	unwrappedVaultKey string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(vaultDir)

	_, err := db.File(
		vaultID,
		unwrappedVaultKey,
		database.FileModeOpenOrCreate,
	)

	return err
}

func (s *Local) CreateOnSot(
	authorizer *tacenvaentity.User,
	recordID *string,
	data []byte,
	lastChangeID *string,
	changeBy string,
) error {
	if !authorizer.HasWriteAccess() {
		return ErrForbidden
	}

	return s.create(
		recordID,
		data,
		lastChangeID,
		changeBy,
	)
}

func (s *Local) CreateOnReplica(
	recordID *string,
	data []byte,
	lastChangeID *string,
) error {
	return s.create(
		recordID,
		data,
		lastChangeID,
		"local",
	)
}

func (s *Local) UpdateOnSot(
	authorizer *tacenvaentity.User,
	recordID string,
	data []byte,
	lastChangeID *string,
	changeBy string,
) error {
	if !authorizer.HasWriteAccess() {
		return ErrForbidden
	}

	return s.update(
		recordID,
		data,
		lastChangeID,
		changeBy,
	)
}

func (s *Local) UpdateOnReplica(
	recordID string,
	data []byte,
	lastChangeID *string,
) error {
	return s.update(
		recordID,
		data,
		lastChangeID,
		"local",
	)
}

func (s *Local) DeleteOnSot(
	authorizer *tacenvaentity.User,
	recordID string,
	lastChangeID *string,
	changeBy string,
) error {
	if !authorizer.HasWriteAccess() {
		return ErrForbidden
	}

	return s.delete(
		recordID,
		lastChangeID,
		changeBy,
	)
}

func (s *Local) DeleteOnReplica(
	recordID string,
	lastChangeID *string,
) error {
	return s.delete(
		recordID,
		lastChangeID,
		"local",
	)
}

func (s *Local) create(
	recordID *string,
	data []byte,
	lastChangeID *string,
	changeBy string,
) error {
	if len(data) == 0 {
		return ErrRecordDataEmpty
	}

	err := s.vaultRawRecordFile.InsertRaw(recordID, data)
	if err != nil {
		return err
	}

	err = s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			*s.entityName,
			*recordID,
			tacenvaentity.OperationCreate,
			*s.sotID,
			changeBy,
		)
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *Local) update(
	recordID string,
	data []byte,
	lastChangeID *string,
	changeBy string,
) error {
	if len(data) == 0 {
		return ErrRecordDataEmpty
	}

	if err := s.vaultRawRecordFile.UpdateRaw(
		recordID,
		data,
	); err != nil {
		return err
	}

	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			*s.entityName,
			recordID,
			tacenvaentity.OperationUpdate,
			*s.sotID,
			changeBy,
		)
	})
}

func (s *Local) delete(
	recordID string,
	lastChangeID *string,
	changeBy string,
) error {
	if err := s.vaultRawRecordFile.DeleteRaw(recordID); err != nil {
		return err
	}

	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			*s.entityName,
			recordID,
			tacenvaentity.OperationDelete,
			*s.sotID,
			changeBy,
		)
	})
}

func (s *Local) List() ([]tacpassentity.VaultRecord, error) {
	var records []tacpassentity.VaultRecord

	err := s.vaultRecordFile.FindAll(
		&records,
	).Order("ID ASC").Error
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (s *Local) GetChangesAfter(
	startID string,
	limit int,
) (*contract.PendingVaultRecordChange, error) {
	return s.repository.GetChangesAfter(
		s.currentVaultDir,
		*s.vaultID,
		*s.sotID,
		startID,
		limit,
	)
}

func (s *Local) SyncOnSot(
	authorizer *tacenvaentity.User,
	sotStartChangeID string,
	limit int,
	replicaChanges *contract.PendingVaultRecordChange,
) (err error) {
	return s.repository.SyncOnSot(
		authorizer,
		s.currentVaultDir,
		*s.sotID,
		*s.vaultID,
		sotStartChangeID,
		limit,
		replicaChanges,
	)
}

func (s *Local) SyncOnReplica(
	changeBase *contract.PendingVaultRecordChange,
	changeComp *contract.PendingVaultRecordChange,
) (err error) {
	return s.repository.SyncOnReplica(
		s.currentVaultDir,
		*s.sotID,
		*s.vaultID,
		changeBase,
		changeComp,
	)
}

func (s *Local) GetChangeCount(
	startID string,
) (int64, error) {
	return s.syncService.GetChangeCount(
		*s.sotID,
		*s.entityName,
		startID,
	)
}

func (s *Local) GetSyncLatestChangeId() (string, error) {
	syncState, err := s.syncService.GetSyncState(
		*s.sotID,
		*s.entityName,
	)

	return syncState.LastChangeID, err
}

func (s *Local) SetSyncStateToBeLatest() error {
	return s.repository.SetSyncStateToBeLatest(
		*s.sotID,
		*s.vaultID,
	)
}
