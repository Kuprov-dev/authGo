package models

import "time"

type User struct {
	Username     string
	Password     string
	RefreshToken string
}

type UserCredentials struct {
	Username     string `json:"username"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshedTokenCreds struct {
	AccessToken           string
	RefreshedToken        string
	RefreshExpirationTime time.Time
	AccessExpirationTime  time.Time
}

type UserDetailResponse struct {
	Username string `json:"username"`
}

type LoginCredentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}
type UserDB struct {
	ID       string `bson:"_id"`
	Username string `bson:"username"`
	Password string `bson:"password"`
}

// TODO separate models and schemes
