package app

import (
	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-core/accesscontrol"
	tacenvaapp "github.com/tacenva/tacenva-core/app"
	"github.com/tacenva/tacenva-core/auth"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"gorm.io/gorm"
)

type Services struct {
	Auth          *auth.Service
	AccessControl *accesscontrol.Service
	Vault         *vault.Service
	VaultAccess   *vaultaccess.Service
	VaultRecord   *vaultrecord.Service
}

func NewServices(
	sqliteDB *gorm.DB,
	tacenvaDB *database.DB,
	sotHostname string,
) *Services {
	tacenvaService := tacenvaapp.NewServices(
		sqliteDB,
		tacenvaDB,
		sotHostname,
	)

	vaultAccessService := vaultaccess.NewService(
		vaultaccess.NewRepository(sqliteDB),
		tacenvaService.AccessControl.PublicKeyOfGroups,
		tacenvaService.AccessControl.List,
	)

	vaultService := vault.NewService(
		vault.NewRepository(sqliteDB),
		vaultAccessService,
		tacenvaService.SyncService,
	)

	vaultRecordService := vaultService.GetVaultRecordService()

	return &Services{
		Auth:          tacenvaService.Auth,
		AccessControl: tacenvaService.AccessControl,
		Vault:         vaultService,
		VaultAccess:   vaultAccessService,
		VaultRecord:   vaultRecordService,
	}
}
