package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	UserIDKey   = "user_id"
	UserTypeKey = "user_type"
	JWTTokenKey = "jwt_token"
)

type GeneralResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func JWTAuthMiddleware(accessTokenSecret string, apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Fetch and validate `x-api-key`` if exists
		client_apiKey := c.GetHeader("x-api-key")
		if apiKey != "" {
			if isValidAPIKey(client_apiKey, apiKey) {
				c.Next() // Early returns for api-key access
				return
			}
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Invalid API Key",
				Code:    http.StatusUnauthorized,
			},
			)
			c.Abort()
			return
		}

		// Fetch and validate authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Invalid or missing authorization header",
				Code:    http.StatusUnauthorized,
			})

			c.Abort()
			return
		}

		// Extract the token from authorization header
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Invalid or missing token",
			},
			)
			c.Abort()
			return
		}

		// Parse the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(accessTokenSecret), nil
		})
		if err != nil {
			log.Printf("[JWT] Error parsing token: %v", err)
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + fmt.Sprintf("Invalid or missing token: %v", err),
			},
			)
			c.Abort()
			return
		}
		if !token.Valid {
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Invalid or missing token",
			},
			)
			c.Abort()
			return
		}

		// Extract claims and set in context
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Error parsing claims",
			},
			)
			c.Abort()
			return
		}

		// Set the userID in the context for later use
		userID, ok := claims["user_id"].(float64)
		if !ok {
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Failed to retrieve `user_id` from token",
				Code:    http.StatusUnauthorized,
			},
			)
			c.Abort()
			return
		}

		userType, ok := claims["user_type"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, GeneralResponse{
				Message: "Unauthorised" + "Failed to retrieve `user_type` from token",
			},
			)
			c.Abort()
			return
		}

		// Store the userID in the context for use in other handlers
		c.Set(JWTTokenKey, tokenString)
		c.Set(UserIDKey, uint(userID))
		c.Set(UserTypeKey, userType)
		c.Next()
	}
}

func isValidAPIKey(apiKey string, actualApiKey string) bool {
	validAPIKeys := map[string]bool{
		actualApiKey: true,
	}
	return validAPIKeys[apiKey]
}
