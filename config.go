package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	democrypto "pq-tls-demo/crypto"
)

// Config is the cryptographic configuration loaded from crypto-policy.yaml.
// Provider and policy are separate concepts.
type Config struct {
	Provider string `yaml:"provider"`
	Policy   string `yaml:"policy"`
}

const defaultPolicyPath = "config/crypto-policy.yaml"

// loadConfig reads and parses the YAML cryptographic policy file.
// Failure to read or parse must fail startup; there is no default provider/policy.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read crypto policy %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse crypto policy %q: %w", path, err)
	}
	if cfg.Provider == "" {
		return nil, fmt.Errorf("crypto policy %q: provider is required (no silent default)", path)
	}
	if cfg.Policy == "" {
		return nil, fmt.Errorf("crypto policy %q: policy is required (no silent default)", path)
	}
	if _, err := democrypto.NewProvider(cfg.Provider); err != nil {
		return nil, fmt.Errorf("crypto policy %q: %w", path, err)
	}
	if _, err := democrypto.ParsePolicyMode(cfg.Policy); err != nil {
		return nil, fmt.Errorf("crypto policy %q: %w", path, err)
	}
	return &cfg, nil
}
