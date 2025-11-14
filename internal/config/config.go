// Package config contains the functionality to load environment variables into a golang-based struct for accessibility
package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// Config defines the structure of env vars that will be loaded to the project
type Config struct {
	BaseAPIUrl         string `envconfig:"BASE_API_URL" required:"true"`
	APIKey             string `envconfig:"API_KEY" required:"true"`
	Port               string `envconfig:"PORT" default:"8086"`
	GoogleClientID     string `envconfig:"GOOGLE_CLIENT_ID" required:"true"`
	GoogleClientSecret string `envconfig:"GOOGLE_CLIENT_SECRET" required:"true"`
	SecretAuthKey      string `envconfig:"SECRET_AUTH_KEY" required:"true"`
}

// Load loads the env vars to the project in a defined go struct for accessibility
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("error loading configuration data, %w", err)
	}
	return &cfg, nil
}
