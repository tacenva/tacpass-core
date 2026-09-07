package vault

import (
	"errors"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/credential"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpass-core/vaultaccess"
)

var (
	ErrNotFound  = errors.New("vault not found")
	ErrNameEmpty = errors.New("vault name cannot be empty")
)

type Service struct {
	repository         *repository
	tacenvaDB          *database.DB
	vaultaccessService *vaultaccess.Service
}

func NewService(
	repository *repository,
	tacenvaDB *database.DB,
	vaultaccessService *vaultaccess.Service,
) *Service {
	return &Service{
		repository:         repository,
		tacenvaDB:          tacenvaDB,
		vaultaccessService: vaultaccessService,
	}
}

func (s *Service) Create(authUser *entity.User, name string, keyPair *keyring.KeyPair) (*entity.VaultAccess, error) {
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

	// Raw key yang dipakai untuk database vault.
	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
	}

	// Encrypt/seal vault key menggunakan public key user.
	sealedVaultKey, err := keyPair.Seal([]byte(vaultKey))
	if err != nil {
		return nil, err
	}

	// Yang disimpan di VaultAccess harus ciphertext.
	vaultAccessData, err := s.vaultaccessService.Create(
		vault.ID,
		authUser.PermissionID,
		sealedVaultKey,
	)
	if err != nil {
		return nil, err
	}

	// Database file tetap menggunakan RAW vault key.
	_, err = s.tacenvaDB.File(
		vault.ID,
		string(vaultKey),
	)
	if err != nil {
		return nil, err
	}

	vaultAccessData.Vault = *vault

	return vaultAccessData, nil
}

func (s *Service) VaultAccessList(
	authUser *entity.User,
) ([]entity.VaultAccess, error) {
	vaulaccesstist, err := s.repository.FindAccessible(authUser.PermissionID)
	if err != nil {
		return nil, err
	}

	return vaulaccesstist, nil
}

func (s *Service) DecryptedRecordList(
	authUser *entity.User,
	vaultId string,
	keyPair *keyring.KeyPair,
) ([]entity.VaultRecord, error) {
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

	vaultKey, err := s.vaultaccessService.GetVaultKey(
		vault.ID,
		authUser.PermissionID,
		keyPair,
	)
	if err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaDB.File(
		vault.ID,
		string(vaultKey),
	)
	if err != nil {
		return nil, err
	}

	var vaultRecord []entity.VaultRecord

	if err = fileDB.FindAll(&vaultRecord); err != nil {
		return nil, err
	}

	return vaultRecord, nil
}

func (s *Service) Update(
	id string,
	name string,
) (*entity.Vault, error) {
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

func (s *Service) createUpdateRecord(
	authUser *entity.User,
	vaultId string,
	keyPair *keyring.KeyPair,
) (*database.DatabaseFile, error) {
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

	vaultKey, err := s.vaultaccessService.GetVaultKey(
		vault.ID,
		authUser.PermissionID,
		keyPair,
	)
	if err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaDB.File(
		vault.ID,
		string(vaultKey),
	)
	if err != nil {
		return nil, err
	}

	return fileDB, nil
}

func (s *Service) AppendRecord(
	authUser *entity.User,
	vaultId string,
	vaultRecord *entity.VaultRecord,
	keyPair *keyring.KeyPair,
) (*entity.VaultRecord, error) {
	fileDB, err := s.createUpdateRecord(
		authUser,
		vaultId,
		keyPair,
	)
	if err != nil {
		return nil, err
	}

	_, err = fileDB.Insert(vaultRecord)
	if err != nil {
		return nil, err
	}

	return vaultRecord, nil
}

func (s *Service) UpdateRecord(
	authUser *entity.User,
	vaultId string,
	vaultRecord *entity.VaultRecord,
	keyPair *keyring.KeyPair,
) (*entity.VaultRecord, error) {
	fileDB, err := s.createUpdateRecord(
		authUser,
		vaultId,
		keyPair,
	)
	if err != nil {
		return nil, err
	}

	err = fileDB.Update(vaultRecord)
	if err != nil {
		return nil, err
	}

	return vaultRecord, nil
}

func (s *Service) Delete(
	id string,
	password string,
) error {
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

	fileDB, err := s.tacenvaDB.File(
		vault.ID,
		password,
	)
	if err != nil {
		return err
	}

	if _, err = fileDB.Delete(vault.ID); err != nil {
		return err
	}

	return nil
}
