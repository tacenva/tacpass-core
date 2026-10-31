package vaultrecord

import (
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	tacpassentity "github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type Local struct {
	syncService *sync.Service

	vaultDir           string
	vaultID            *string
	vaultRawRecordFile *database.DatabaseFile
	vaultRecordFile    *database.DatabaseFile
	entityName         *string
}

func NewLocalService(
	syncService *sync.Service,
	vaultDir string,
) *Local {
	return &Local{
		syncService: syncService,
		vaultDir:    vaultDir,
	}
}

func (s *Local) SetConfig(
	vaultID string,
	unwrappedVaultKey string,
) error {
	s.vaultID = &vaultID

	db := database.New(s.vaultDir)
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
	return nil
}

func (s *Local) SimulateEncryption(
	record *tacpassentity.VaultRecord,
) (string, error) {
	return s.vaultRecordFile.SimulateEncryption(record)
}

func (s *Local) Init(
	vaultID string,
	unwrappedVaultKey string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(s.vaultDir)

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
	sotID string,
	lastChangeID *string,
	changeBy string,
) error {
	// if !auth.HasWritePermission() {
	// 	return ErrForbidden
	// }

	return s.create(
		recordID,
		data,
		sotID,
		lastChangeID,
		changeBy,
	)
}

func (s *Local) CreateOnReplica(
	recordID *string,
	data []byte,
	sotID string,
	lastChangeID *string,
) error {
	return s.create(
		recordID,
		data,
		sotID,
		lastChangeID,
		"local",
	)
}

func (s *Local) UpdateOnSot(
	authorizer *tacenvaentity.User,
	recordID string,
	data []byte,
	sotID string,
	lastChangeID *string,
	changeBy string,
) error {
	// if !auth.HasWritePermission() {
	// 	return ErrForbidden
	// }
	return s.update(
		recordID,
		data,
		sotID,
		lastChangeID,
		changeBy,
	)
}

func (s *Local) UpdateOnReplica(
	recordID string,
	data []byte,
	sotID string,
	lastChangeID *string,
) error {
	return s.update(
		recordID,
		data,
		sotID,
		lastChangeID,
		"local",
	)
}

func (s *Local) DeleteOnSot(
	authorizer *tacenvaentity.User,
	recordID string,
	sotID string,
	lastChangeID *string,
	changeBy string,
) error {
	// if !auth.HasWritePermission() {
	// 	return ErrForbidden
	// }

	return s.delete(
		recordID,
		sotID,
		lastChangeID,
		changeBy,
	)
}

func (s *Local) DeleteOnReplica(
	recordID string,
	sotID string,
	lastChangeID *string,
) error {
	return s.delete(
		recordID,
		sotID,
		lastChangeID,
		"local",
	)
}

func (s *Local) create(
	recordID *string,
	data []byte,
	sotID string,
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
			sotID,
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
	sotID string,
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
			sotID,
			changeBy,
		)
	})
}

func (s *Local) delete(
	recordID string,
	sotID string,
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
			sotID,
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
