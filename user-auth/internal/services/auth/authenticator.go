package auth

import (
	"context"
	"time"
	"user-auth/internal/entities"
)

type Authenticator interface {
	Login(credentials LoginCredentials, userType string, ctx context.Context) (entities.UserInterface, error)
	GetTimeNow() time.Time
	VerifyPassword(plainPassword, userType string, userID uint, ctx context.Context) error
}

type LoginCredentials struct {
	Email    string `json:"Email"`
	Password string `json:"Password"`
	//ID           string `json:"ID"`
	//PasswordHash string
	OAuth2Token string
	Provider    string
}
