package vault

import (
	"errors"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
)

var (
	ErrNotFound  = errors.New("vault not found")
	ErrNameEmpty = errors.New("vault name cannot be empty")
)

type Service struct {
	repository    *repository
	vaultRecordDB *database.DB
}

func NewService(repository *repository, vaultRecordDB *database.DB) *Service {
	return &Service{
		repository:    repository,
		vaultRecordDB: vaultRecordDB,
	}
}

func (s *Service) Create(name string, password string) (*entity.Vault, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return nil, ErrNameEmpty
	}

	vault := &entity.Vault{
		Name: name,
	}

	if err := s.repository.Create(vault); err != nil {
		return nil, err
	}

	_, err := s.vaultRecordDB.File(vault.ID, password)
	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) Get(id string, password string) (*entity.Vault, []entity.VaultRecord, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, nil, ErrNotFound
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return nil, nil, err
	}

	if vault == nil {
		return nil, nil, ErrNotFound
	}

	fileDB, err := s.vaultRecordDB.File(vault.ID, password)
	if err != nil {
		return nil, nil, err
	}

	var vaultRecord []entity.VaultRecord
	if err = fileDB.FindAll(&vaultRecord); err != nil {
		return nil, nil, err
	}

	return vault, vaultRecord, nil
}

func (s *Service) List() ([]entity.Vault, error) {
	return s.repository.FindAll()
}

func (s *Service) Update(id string, name string) (*entity.Vault, error) {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)

	if id == "" {
		return nil, ErrNotFound
	}

	if name == "" {
		return nil, ErrNameEmpty
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if vault == nil {
		return nil, ErrNotFound
	}

	vault.Name = name

	if err := s.repository.Update(vault); err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) UpdateRecord(vaultId string, vaultRecord *entity.VaultRecord, password string) (*entity.VaultRecord, error) {
	vaultId = strings.TrimSpace(vaultId)

	if vaultId == "" {
		return nil, ErrNotFound
	}

	vault, err := s.repository.FindByID(vaultId)
	if err != nil {
		return nil, err
	}

	fileDB, err := s.vaultRecordDB.File(vault.ID, password)
	if err != nil {
		return nil, err
	}

	err = fileDB.Update(&vaultRecord)
	if err != nil {
		return nil, err
	}

	return vaultRecord, nil
}

func (s *Service) Delete(id string, password string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if vault == nil {
		return ErrNotFound
	}

	if err = s.repository.Delete(id); err != nil {
		return err
	}

	fileDB, err := s.vaultRecordDB.File(vault.ID, password)
	if err != nil {
		return err
	}

	if _, err = fileDB.Delete(vault.ID); err != nil {
		return err
	}

	return nil
}
