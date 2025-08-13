package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"user-auth/internal/controller"
	"user-auth/internal/entities"
	"user-auth/internal/repo/mockrepo"
	"user-auth/internal/router"
	"user-auth/internal/services"
	"user-auth/pkg/utils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTestController() controller.Controller {
	mockRepo := &mockrepo.MockMsqlRepository{
		CreateUserMemberFunc: func(userType, authType string, user entities.UserInterface, ctx context.Context) (uint, error) {
			// Return a fake user ID, no error
			return 12345, nil
		},
	}
	svc := services.NewServices(mockRepo)
	return controller.NewController(svc)
}

func setupRouter(ctrl controller.Controller) *gin.Engine {
	r := gin.Default()
	router.SetupRouter(r, ctrl, "testApiKey", "testAccessTokenSecret")
	return r
}

func TestRegisterHandler(t *testing.T) {
	ctrl := setupTestController()
	r := setupRouter(ctrl)

	user := utils.GenerateRandomUser()

	requestBody := map[string]interface{}{
		"authType": "email",
		"userType": "user_member",
		"body":     user,
	}

	bodyBytes, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewBuffer(bodyBytes))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()

	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusCreated, resp.Code)

	t.Logf("Response Body: %s", resp.Body.String())
}
