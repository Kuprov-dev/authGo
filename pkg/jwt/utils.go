package jwt

import (
	"auth_service/pkg/models"
	"context"
	"fmt"
)

type ContextKey string

var ContextUserCredsKey ContextKey = "userCreds"
var ContextTokenCredsKey ContextKey = "tokenCreds"

func PassUserCredsInContext(userCreds *models.UserCredentials, reqCtx context.Context) context.Context {
	return context.WithValue(reqCtx, ContextUserCredsKey, userCreds)
}

func PassTokenCredsInContext(tokenCreds *models.TokenCredentials, reqCtx context.Context) context.Context {
	return context.WithValue(reqCtx, ContextTokenCredsKey, tokenCreds)
}

func GetTokenCredsFromContext(ctx context.Context) (*models.TokenCredentials, error) {
	tokenCreds, ok := ctx.Value(ContextTokenCredsKey).(*models.TokenCredentials)
	if !ok {
		return nil, fmt.Errorf("Cannot get token creds from context.")
	}
	return tokenCreds, nil
}

func GetUserCredsFromContext(ctx context.Context) (*models.UserCredentials, error) {
	userCreds, ok := ctx.Value(ContextUserCredsKey).(*models.UserCredentials)
	if !ok {
		return nil, fmt.Errorf("Cannot get user creds from context.")
	}
	return userCreds, nil
}
