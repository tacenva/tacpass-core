package vaultrecord

import (
	"errors"

	"github.com/tacenva/tacenva-core/sync"
)

var (
	ErrForbidden       = errors.New("forbidden")
	ErrVaultIDEmpty    = errors.New("vault ID cannot be empty")
	ErrRecordIDEmpty   = errors.New("record ID cannot be empty")
	ErrRecordDataEmpty = errors.New("record data cannot be empty")
)

const syncEntityVaultRecord = "vault_record"

type Service struct {
	repository *repository
	Local      *Local
	Remote     *Remote
}

func NewService(
	syncService *sync.Service,
	repository *repository,
) *Service {
	return &Service{
		Local: NewLocalService(
			syncService,
			repository,
		),

		Remote: NewRemoteService(
			syncService,
			repository,
		),
	}
}

func (s *Service) Destroy(
	vaultDir string,
	vaultID string,
) error {
	return s.repository.Destroy(
		vaultDir,
		vaultID,
	)
}
