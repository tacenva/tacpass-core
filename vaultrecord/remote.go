package vaultrecord

import (
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
)

type Remote struct {
	syncService *sync.Service
	repository  *repository

	vaultDir        *string
	vaultRecordFile *database.DatabaseFile
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

	db := database.New(*s.vaultDir)

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
	// if !authorizer.HasWritePermission() {
	// 	return ErrForbidden
	// }

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(*s.vaultDir)

	err := db.Write(vaultID, data)
	if err != nil {
		return err
	}

	return nil
}
