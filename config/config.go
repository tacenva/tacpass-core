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

	DefaultPort = 49153
)

type Config struct {
	BaseDir string `toml:"-"`

	SotID  string       `toml:"sot_id"`
	Server ServerConfig `toml:"server"`
	TLS    TLSConfig    `toml:"tls"`
}

type ServerConfig struct {
	Port     int    `toml:"port"`
	Hostname string `toml:"hostname"`
}

type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

func Default() (*Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf(
			"get hostname: %w",
			err,
		)
	}

	return &Config{
		Server: ServerConfig{
			Port:     DefaultPort,
			Hostname: hostname,
		},
		TLS: TLSConfig{
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
		},
	}, nil
}

func (cfg *Config) Path(parts ...string) string {
	return filepath.Join(
		append([]string{cfg.BaseDir}, parts...)...,
	)
}

func (cfg *Config) VaultDir() string {
	return cfg.Path(
		NodeDirName,
		cfg.SotID,
		"vault",
	)
}

func (cfg *Config) setSotID(sotID string) error {
	if sotID == "" {
		return fmt.Errorf("sot ulid is required")
	}

	cfg.SotID = sotID

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
		return fmt.Errorf(
			"config base directory is required",
		)
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

	configPath := cfg.Path(
		ConfigFileName,
	)

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

func Load(dev bool) (*Config, error) {
	baseDir, err := getBaseDir(dev)
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

	cfg, err := Default()
	if err != nil {
		return nil, err
	}

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

func LoadOrCreate(dev bool) (*Config, error) {
	baseDir, err := getBaseDir(dev)
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(
		baseDir,
		ConfigFileName,
	)

	if _, err := os.Stat(configPath); err == nil {
		cfg, err := Load(dev)
		if err != nil {
			return nil, err
		}

		if cfg.SotID == "" {
			if err := cfg.setSotID(
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

	cfg, err := Default()
	if err != nil {
		return nil, err
	}

	cfg.BaseDir = baseDir

	if err := cfg.setSotID(
		ulid.Make().String(),
	); err != nil {
		return nil, err
	}

	return cfg, nil
}

func getBaseDir(dev bool) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf(
			"get home directory: %w",
			err,
		)
	}

	dirName := ConfigDirName

	if dev {
		dirName += "-dev"
	}

	return filepath.Join(
		homeDir,
		dirName,
	), nil
}
