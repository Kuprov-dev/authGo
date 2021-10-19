package conf

import "auth_service/pkg/env"

// Конфиги приложения из енв
type Config struct {
	Port             string
	SecretKeyAccess  string
	SecretKeyRefresh string
}

func New() *Config {
	return &Config{
		Port:             env.GetEnv("PORT", "8000"),
		SecretKeyAccess:  env.GetEnv("ACCESS_SECRET", "secretsecret"),
		SecretKeyRefresh: env.GetEnv("REFRESH_SECRET", "epstein didn't kill himself"),
	}
}
