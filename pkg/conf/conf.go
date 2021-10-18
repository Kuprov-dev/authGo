package conf

import "auth_service/pkg/env"

type Config struct {
	Port      string
	SecretKey string
}

func New() *Config {
	return &Config{
		Port:      env.GetEnv("PORT", "8000"),
		SecretKey: env.GetEnv("SECRET", "secretsecret"),
	}
}
