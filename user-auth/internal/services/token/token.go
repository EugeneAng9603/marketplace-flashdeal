package token

import (
	"context"
	"errors"
	"log"
	"time"
	"user-auth/internal/entities"
	"user-auth/internal/repo"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService interface {
	GenerateAccessToken(userID uint, userType string) (string, error)
	GenerateRefreshToken(userID uint, userType string) (string, error)
	ValidateToken(tokenString string) (*jwt.Token, error)
	GetUserIDFromToken(token *jwt.Token) (uint, error)
	GetClaimFromToken(token *jwt.Token) (*entities.JwtClaim, error)
}

type tokenService struct {
	repo               repo.MsqlRepository
	accessTokenSecret  string
	refreshTokenSecret string
	accessTTL          time.Duration
	refreshTTL         time.Duration
}

func NewTokenService(accessTokenSecret string, refreshTokenSecret string, accessTTL time.Duration, refreshTTL time.Duration, repo repo.MsqlRepository) TokenService {
	return &tokenService{
		repo:               repo,
		accessTokenSecret:  accessTokenSecret,
		refreshTokenSecret: refreshTokenSecret,
		accessTTL:          accessTTL,
		refreshTTL:         refreshTTL,
	}
}

func (s *tokenService) GenerateAccessToken(userID uint, userType string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"user_type": userType,
		"exp":       time.Now().Add(s.accessTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.accessTokenSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (s *tokenService) GenerateRefreshToken(userID uint, userType string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"user_type": userType,
		"exp":       time.Now().Add(s.refreshTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.refreshTokenSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// first check if blacklisted, if not, then check if token is valid, lastly check if token is expired
func (s *tokenService) ValidateToken(tokenString string) (*jwt.Token, error) {
	isBlacklisted, err := s.repo.IsTokenBlacklisted(tokenString, context.Background())
	if err != nil {
		return nil, err
	}
	if isBlacklisted {
		return nil, errors.New("token is blacklisted")
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		log.Println("Token signing method is valid.")
		return []byte(s.refreshTokenSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// validate (expiration) claim and token is not expired
		if exp, ok := claims["exp"].(float64); ok {
			log.Printf("Expiration claim: %v", exp)
			if int64(exp) < time.Now().Unix() {
				log.Println("Token has expired.")
				return nil, errors.New("token has expired")
			}
		} else {
			return nil, errors.New("expiration claim is missing or invalid")
		}
		return token, nil
	} else {
		return nil, errors.New("invalid token")
	}
}

func (s *tokenService) GetUserIDFromToken(token *jwt.Token) (uint, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("invalid token claims")
	}
	// Extract user_id, asserting it as float64 (since JWT decoding defaults to float64)
	userID, ok := claims["user_id"].(float64)
	if !ok {
		return 0, errors.New("user_id claim is not a valid number")
	}

	return uint(userID), nil
}
func (s *tokenService) GetClaimFromToken(token *jwt.Token) (*entities.JwtClaim, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &entities.JwtClaim{}, errors.New("invalid token claims")
	}
	// Extract user_id, asserting it as float64 (since JWT decoding defaults to float64)
	userID, ok := claims["user_id"].(float64)
	if !ok {
		return &entities.JwtClaim{}, errors.New("user_id claim is not a valid number")
	}
	userType, ok := claims["user_type"].(string)
	if !ok {
		return &entities.JwtClaim{}, errors.New("user_type claim is not a valid string")
	}

	claimFromToken := &entities.JwtClaim{
		UserID:   uint(userID),
		UserType: userType,
	}
	return claimFromToken, nil
}
