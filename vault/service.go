package vault

import (
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"gorm.io/gorm"
)

const syncEntityVault = "vault"

type Service struct {
	repository         *repository
	vaultaccessService *vaultaccess.Service
	vaultRecordService *vaultrecord.Service
	syncService        *sync.Service

	Sot     *SotService
	Replica *ReplicaService
}

func NewService(
	repository *repository,
	vaultaccessService *vaultaccess.Service,
	syncService *sync.Service,
) *Service {
	vaultrecordRepository := vaultrecord.NewRepository(
		repository.db,
		syncService,
	)
	vaultrecordService := vaultrecord.NewService(
		vaultrecordRepository,
		vaultaccessService.Exists,
	)
	return &Service{
		repository:         repository,
		vaultRecordService: vaultrecordService,
		vaultaccessService: vaultaccessService,
		syncService:        syncService,

		Sot: NewSotService(
			repository,
			vaultaccessService,
			vaultrecordService,
			syncService,
		),
		Replica: NewReplicaService(
			repository,
			vaultrecordService,
			syncService,
		),
	}
}

func (s *Service) GetVaultRecordService() *vaultrecord.Service {
	return s.vaultRecordService
}

func (s *Service) GetSyncLatestChangeID(
	sotID string,
) (string, error) {
	vaultSyncState, err := s.syncService.GetSyncState(
		sotID,
		syncEntityVault,
	)
	if err != nil {
		return "", nil
	}

	return vaultSyncState.LastChangeID, err
}

func (s *Service) SetSyncStateToBeLatest(
	sotID string,
) error {
	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.SetSyncStateToBeLatest(
			tx,
			sotID,
			syncEntityVault,
		)
	})
}

func (s *Service) AllAccessGroup(
	sotID string,
) ([]tacenvaentity.AccessGroup, error) {
	return s.vaultaccessService.AllAccessGroup(
		sotID,
	)
}

func (s *Service) SyncGroups(
	sotID string,
	groups []tacenvaentity.AccessGroup,
	lastSyncChange *tacenvaentity.SyncChange,
) error {
	return s.vaultaccessService.SyncGroups(
		sotID,
		groups,
		lastSyncChange,
	)
}
