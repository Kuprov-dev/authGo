package models

type User struct {
	Username     string
	Password     string
	RefreshToken string
}



type UserCredentials struct {
	Username string `json:"username"`
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
