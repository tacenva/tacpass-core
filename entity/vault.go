package entity

import (
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

type VaultRecord struct {
	ID        string    `json:"id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Password  string    `json:"password,omitempty"`
	ExpiredAt time.Time `json:"expired_at,omitempty"`
}

type Vault struct {
	ID        string    `json:"id,omitempty" gorm:"type:varchar(26);primaryKey"`
	Name      string    `json:"name,omitempty" gorm:"type:varchar(255);not null"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	WrappedKey string   `json:"wrapped_key,omitempty" gorm:"-"`
	GroupIDs   []string `json:"group_ids" gorm:"serializer:json;type:text;not null"`
}

func (p *Vault) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = ulid.Make().String()
	}

	return nil
}
