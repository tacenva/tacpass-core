package vault

import (
	"errors"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/util/credential"
	"github.com/tacenva/tacpass-core/vaultaccess"
)

var (
	ErrNotFound  = errors.New("vault not found")
	ErrNameEmpty = errors.New("vault name cannot be empty")
)

type Service struct {
	repository    *repository
	vaultRecordDB *database.DB

	permissionService  *permission.Service
	vaultaccessService *vaultaccess.Service
}

func NewService(
	repository *repository,
	vaultRecordDB *database.DB,
	permissionService *permission.Service,
	vaultaccessService *vaultaccess.Service,
) *Service {
	return &Service{
		repository:         repository,
		vaultRecordDB:      vaultRecordDB,
		permissionService:  permissionService,
		vaultaccessService: vaultaccessService,
	}
}

func (s *Service) Create(name string, authToken string) (*entity.Vault, error) {
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

	permission, err := s.permissionService.GetByToken(authToken)
	if err != nil {
		return nil, err
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
	}

	_, err = s.vaultaccessService.Create(vault.ID, permission.ID, vaultKey)
	if err != nil {
		return nil, err
	}

	_, err = s.vaultRecordDB.File(vault.ID, vaultKey)
	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) VaultList(authToken string) ([]entity.Vault, error) {
	permission, err := s.permissionService.GetByToken(authToken)
	if err != nil {
		return nil, err
	}

	return s.repository.FindAccessible(permission.ID)
}

func (s *Service) RecordList(vaultId string, privateKey string) ([]entity.VaultRecord, error) {
	vaultId = strings.TrimSpace(vaultId)

	if vaultId == "" {
		return nil, ErrNotFound
	}

	vault, err := s.repository.FindByID(vaultId)
	if err != nil {
		return nil, err
	}

	if vault == nil {
		return nil, ErrNotFound
	}

	// s.vaultaccessService.Get()

	fileDB, err := s.vaultRecordDB.File(vault.ID, privateKey)
	if err != nil {
		return nil, err
	}

	var vaultRecord []entity.VaultRecord
	if err = fileDB.FindAll(&vaultRecord); err != nil {
		return nil, err
	}

	return vaultRecord, nil
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
