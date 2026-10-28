package vault

import (
	"errors"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"gorm.io/gorm"
)

var (
	ErrNotFound   = errors.New("vault not found")
	ErrNameEmpty  = errors.New("vault name cannot be empty")
	ErrPermission = errors.New("permission denied")
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
	)
	vaultrecordService := vaultrecord.NewService(
		syncService,
		vaultrecordRepository,
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

func (s *Service) GetChangeCount(
	sotID string,
	syncLastChangeID string,
) (*contract.PendingTotalChanges, error) {
	vaultChangeCount, err := s.syncService.GetChangeCount(
		sotID,
		syncEntityVault,
		syncLastChangeID,
	)
	if err != nil {
		return nil, err
	}

	return &contract.PendingTotalChanges{
		Count: vaultChangeCount,
	}, nil
}

func (s *Service) SetSyncStateToBeLastest(
	sotID string,
) error {
	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.SetSyncStateToBeLastest(
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
