package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/oklog/ulid/v2"
)

const (
	ConfigDirName  = ".tacenva"
	ConfigFileName = "config.toml"

	AppDBFileName                = "tacenva.db"
	CredentialCollectionFileName = "keypair.tacenva"
	NodeDirName                  = "node"
)

type Config struct {
	BaseDir string `toml:"-"`

	SoTULID string       `toml:"sot_ulid"`
	Server  ServerConfig `toml:"server"`
	TLS     TLSConfig    `toml:"tls"`
}

type ServerConfig struct {
	Port int `toml:"port"`
}

type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

func Default() *Config {
	baseDir, _ := getBaseDir()

	return &Config{
		BaseDir: baseDir,
		Server: ServerConfig{
			Port: 9443,
		},
		TLS: TLSConfig{
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
		},
	}
}

func (cfg *Config) Path(parts ...string) string {
	return filepath.Join(
		append([]string{cfg.BaseDir}, parts...)...,
	)
}

func (cfg *Config) VaultDir() string {
	return cfg.Path("node", cfg.SoTULID, "vault")
}

func (cfg *Config) setSoTULID(sotULID string) error {
	if sotULID == "" {
		return fmt.Errorf("sot ulid is required")
	}

	cfg.SoTULID = sotULID

	if err := cfg.Save(); err != nil {
		return fmt.Errorf(
			"save sot ulid: %w",
			err,
		)
	}

	return nil
}

func (cfg *Config) Save() error {
	if cfg.BaseDir == "" {
		baseDir, err := getBaseDir()
		if err != nil {
			return err
		}

		cfg.BaseDir = baseDir
	}

	if err := os.MkdirAll(
		cfg.BaseDir,
		0755,
	); err != nil {
		return fmt.Errorf(
			"create config directory: %w",
			err,
		)
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf(
			"encode config: %w",
			err,
		)
	}

	configPath := cfg.Path(ConfigFileName)

	if err := os.WriteFile(
		configPath,
		data,
		0644,
	); err != nil {
		return fmt.Errorf(
			"write config: %w",
			err,
		)
	}

	return nil
}

func Load() (*Config, error) {
	baseDir, err := getBaseDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(
		baseDir,
		ConfigFileName,
	)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read config: %w",
			err,
		)
	}

	cfg := Default()
	cfg.BaseDir = baseDir

	if _, err := toml.Decode(
		string(data),
		cfg,
	); err != nil {
		return nil, fmt.Errorf(
			"decode config: %w",
			err,
		)
	}

	cfg.BaseDir = baseDir

	return cfg, nil
}

func LoadOrCreate() (*Config, error) {
	baseDir, err := getBaseDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(
		baseDir,
		ConfigFileName,
	)

	if _, err := os.Stat(configPath); err == nil {
		cfg, err := Load()
		if err != nil {
			return nil, err
		}

		if cfg.SoTULID == "" {
			if err := cfg.setSoTULID(
				ulid.Make().String(),
			); err != nil {
				return nil, err
			}
		}

		return cfg, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"check config: %w",
			err,
		)
	}

	cfg := Default()

	if err := cfg.setSoTULID(
		ulid.Make().String(),
	); err != nil {
		return nil, err
	}

	return cfg, nil
}

func getBaseDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf(
			"get home directory: %w",
			err,
		)
	}

	return filepath.Join(
		homeDir,
		ConfigDirName,
	), nil
}
