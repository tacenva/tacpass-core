package entity

import (
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

type VaultRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	Password  string    `json:"password"`
	ExpiredAt time.Time `json:"expired_at"`
}

type Vault struct {
	ID   string `json:"id" gorm:"type:varchar(26);primaryKey"`
	Name string `json:"name" gorm:"type:varchar(255);not null"`
}

func (p *Vault) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = ulid.Make().String()
	}

	return nil
}
