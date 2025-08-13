package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"time"
	"user-auth/internal/entities"
	"user-auth/internal/services"
	"user-auth/internal/services/auth"
	"user-auth/pkg/utils"

	"github.com/gin-gonic/gin"
)

type Controller interface {
	Login(c *gin.Context)
	Register(c *gin.Context)
	Logout(c *gin.Context)
	GetUserByID(c *gin.Context)
	// ResetPassword(c *gin.Context)
	// ForgotPassword(c *gin.Context)
	// GetUserByMobile(c *gin.Context)
	// GetUserByMobileCard(c *gin.Context)
	// GetDeleteLogs(c *gin.Context)
	// GetEmails(c *gin.Context)
	// GetUsersByBUserIDs(c *gin.Context)
	// UpdateUserDetails(c *gin.Context)
	// UpdatePassword(c *gin.Context)
	// GetAllUsers(c *gin.Context)
	// GetEmailsByIDs(c *gin.Context)
	// GetUsersAdminOnly(c *gin.Context)
	// GetTelegramIDs(c *gin.Context)
	// RefreshToken(c *gin.Context)
}

type controller struct {
	services services.Services
}

func NewController(services services.Services) Controller {
	return &controller{
		services: services,
	}
}

type GeneralRequest struct {
	UserType string      `json:"userType"`
	AuthType string      `json:"authType"`
	Body     interface{} `json:"body"`
}

type GeneralResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func WriteSuccessJSON(c *gin.Context, data any) {
	c.JSON(http.StatusOK, GeneralResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    data,
	})
}

func WriteErrorJSON(c *gin.Context, status int, message string) {
	c.JSON(status, GeneralResponse{
		Code:    status,
		Message: utils.CapitalizeFirstLetter(message),
	})
}

type LoginResponse struct {
	User         entities.UserInterface `json:"user"`
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
}

func (h *controller) Login(c *gin.Context) {
	var request GeneralRequest
	var response GeneralResponse
	defaultResponse := GeneralResponse{
		Message: "Login Failed. ",
		// HttpError: &httputil.HttpError{
		// 	Method:    "POST",
		// 	URL:       c.Request.URL.String(),
		// 	Timestamp: time.Now(),
		// },
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		// Modify only the specific fields for this error
		response = defaultResponse
		response.Code = http.StatusBadRequest
		response.Message += err.Error()

		c.JSON(http.StatusBadRequest, response)
		return
	}

	// Check if UserType and ProjectID are provided
	if request.UserType == "" || request.AuthType == "" || request.Body == nil {
		response = defaultResponse
		response.Code = http.StatusBadRequest
		response.Message += "UserType, ProjectID, AuthType, Body are required"

		c.JSON(http.StatusBadRequest, response)
		return
	}

	var credentials auth.LoginCredentials
	if err := h.BindBodyToStruct(request.Body, &credentials); err != nil {
		response = defaultResponse
		response.Code = http.StatusBadRequest
		response.Message += fmt.Sprintf("Error binding body (credentials) to %s type: %v", request.AuthType, err)

		c.JSON(http.StatusBadRequest, response)
		return
	}

	// Create a new context from gin.Context, but not a good practice to access gin.context from service layer.
	ctx := c.Request.Context()
	user, accessToken, refreshToken, err := h.services.Login(credentials, request.AuthType, request.UserType, ctx)
	if err != nil {
		// c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		// return

		response = defaultResponse
		response.Code = http.StatusUnauthorized
		response.Message += err.Error()

		c.JSON(http.StatusUnauthorized, response)
		return
	}

	loc, _ := time.LoadLocation("Asia/Singapore")
	user.SetUpdatedAt(user.GetUpdatedAt().In(loc))

	responseBody := LoginResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	response = defaultResponse
	response.Message = "Login Successful"
	response.Data = responseBody
	response.Code = http.StatusOK

	c.JSON(http.StatusOK, response)
}

func (h *controller) Register(c *gin.Context) {
	// since we are binding twice, use ShouldBindBodyWith to bind the JSON body to the struct instead of ShouldBindJSON
	// https://github.com/gin-gonic/gin/issues/1078

	// if err := c.ShouldBindBodyWith(&userType, binding.JSON); err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
	// 	return
	// }

	var userType string

	var user entities.UserInterface
	var request GeneralRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Invalid request body" + fmt.Sprintf("Error binding body to %s type: %v, "+
				"please use string type for authType, userType and proper body",
				request.AuthType, err,
			),
			Code: http.StatusBadRequest,
		},
		)
		return
	}

	if request.UserType == "" || request.AuthType == "" || request.Body == nil {
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Invalid request body" + "field: user_type/project_id/auth_type, message: UserType, ProjectID, AuthType are required",
			Code:    http.StatusBadRequest,
		},
		)
		return
	}

	// credentials, ok := request.Body.(auth.LoginCredentials)
	// if !ok {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid register credentials"})
	// 	return
	// }

	// Disallow user to update time through request body, implement later when free

	switch request.UserType {
	case "user_member":
		var user_member entities.UserMember
		if err := h.BindBodyToStruct(request.Body, &user_member); err != nil {
			c.JSON(http.StatusBadRequest, GeneralResponse{
				Message: "Invalid request body" + fmt.Sprintf("Error binding body to %s type: %v, payload/body is inappropriate",
					request.AuthType, err),
				Code: http.StatusBadRequest,
			},
			)
			return
		}
		user = &user_member
		userType = "user_member"

	default:
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Invalid user_type" + "field: user_type, message: expecting `KMSadmin` or `KMSuser`",
			Code:    http.StatusBadRequest,
		},
		)
		return
	}

	var userTypeName string
	if userType == "KMSadmin" {
		userTypeName = "admin"
	} else {
		userTypeName = "user"
	}

	userID, err := h.services.Register(request.UserType, request.AuthType, user, context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, GeneralResponse{
			Message: fmt.Sprintf("Failed to register %s account", userTypeName) + err.Error(),
			Code:    http.StatusInternalServerError,
		},
		)
		return
	}

	c.JSON(http.StatusCreated, GeneralResponse{
		Message: "Success",
		Data:    userID,
		Code:    http.StatusCreated,
	})
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *controller) Logout(c *gin.Context) {
	var refreshTokenInput LogoutRequest
	if err := c.ShouldBindJSON(&refreshTokenInput); err != nil {
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Invalid request body" + err.Error(),
			Code:    http.StatusBadRequest,
		},
		)
		return
	}

	if refreshTokenInput.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Missing refresh token" + "field: refresh_token, message: refresh token is required",
			Code:    http.StatusBadRequest,
		},
		)
		return
	}

	err := h.services.Logout(refreshTokenInput.RefreshToken, c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, GeneralResponse{
			Message: "Failed to logout user account" + err.Error(),
			Code:    http.StatusInternalServerError,
		},
		)
		return
	}

	c.JSON(http.StatusOK, GeneralResponse{Message: "Success", Code: http.StatusOK, Data: true})
}

type GetUserByIDRequest struct {
	UserType string `json:"userType"`
}

func (h *controller) GetUserByID(c *gin.Context) {
	var GetUserByIDRequest GetUserByIDRequest
	if err := c.ShouldBindJSON(&GetUserByIDRequest); err != nil {
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Invalid request body" + err.Error(),
			Code:    http.StatusBadRequest,
		},
		)
		return
	}

	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32) // base 10, 32 bits
	if err != nil {
		c.JSON(http.StatusBadRequest, GeneralResponse{
			Message: "Invalid or missing user_id" + "field: user_id, message: Invalid or missing user ID",
			Code:    http.StatusBadRequest,
		},
		)
		return
	}

	user, err := h.services.GetUserByID(uint(userID), GetUserByIDRequest.UserType, c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, GeneralResponse{
			Message: "Failed to get user by user_id" + err.Error(),
			Code:    http.StatusInternalServerError,
		},
		)
		return
	}
	c.JSON(http.StatusOK, GeneralResponse{
		Message: "Success",
		Data:    user,
		Code:    http.StatusOK,
	})
}

// type RefreshTokenRequest struct {
// 	RefreshToken string `json:"refresh_token"`
// 	UserType     string `json:"userType"`
// }

// func (h *controller) RefreshToken(c *gin.Context) {
// 	var refreshTokenInput RefreshTokenRequest
// 	if err := c.ShouldBindJSON(&refreshTokenInput); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			Code:    http.StatusBadRequest,
// 		})
// 		return
// 	}

// 	if refreshTokenInput.RefreshToken == "" {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Missing refresh token, refresh token is required",
// 			Code:    http.StatusBadRequest,
// 		})
// 		return
// 	}

// 	newAccessToken, newRefreshToken, err := h.services.RefreshToken(refreshTokenInput.RefreshToken, refreshTokenInput.UserType, c.Request.Context())
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to refresh token",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusInternalServerError,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	response := struct {
// 		AccessToken  string `json:"access_token"`
// 		RefreshToken string `json:"refresh_token"`
// 	}{
// 		AccessToken:  newAccessToken,
// 		RefreshToken: newRefreshToken,
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    response,
// 	})
// }

// BindBodyToStruct will attempt to bind the provided "body" field (interface{}) to the given target struct.
// Target is the struct we want to bind the body data into (e.g., KMSAdmin).
func (h *controller) BindBodyToStruct(body interface{}, target interface{}) error {
	// Assert the body into a map (which is a common structure for JSON)
	bodyData, ok := body.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid body data format: expected a JSON object, got %T", body)
	}

	// Marshal the bodyData map to raw JSON bytes
	bodyBytes, err := json.Marshal(bodyData)
	if err != nil {
		return fmt.Errorf("failed to marshal body data: %v", err)
	}

	// Unmarshal the raw JSON into the target struct
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to unmarshal body data into target struct: %v", err)
	}

	return nil
}

func (h *controller) BindBodyToStructEnhanced(body interface{}, target interface{}) error {
	// Case 1: If the body is already a JSON object (i.e., map[string]interface{} or a struct)
	switch v := body.(type) {
	case map[string]interface{}:
		bodyBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal body data: %v", err)
		}
		if err := json.Unmarshal(bodyBytes, target); err != nil {
			return fmt.Errorf("failed to unmarshal body data into target struct: %v", err)
		}
		return nil
	}

	// Case 2: If the body is an array (e.g., []interface{} or []int)
	switch v := body.(type) {
	case []interface{}:
		// Example: Convert []interface{} to []uint
		var result []uint
		for _, item := range v {
			if num, ok := item.(float64); ok { // JSON numbers are parsed as float64
				result = append(result, uint(num))
			} else {
				return fmt.Errorf("invalid item in array, expected number but got %T", item)
			}
		}

		// Now, assign the result to the target
		// We use reflection to assign the result to the target
		targetValue := reflect.ValueOf(target)
		if targetValue.Kind() != reflect.Ptr || targetValue.IsNil() {
			return fmt.Errorf("target must be a pointer")
		}
		targetValue.Elem().Set(reflect.ValueOf(result))

		return nil
	}

	// Case 3: Default case - if the body is not recognized, return an error
	return fmt.Errorf("invalid body data format: expected a JSON object or an array, got %T", body)
}

// type ResetPasswordInput struct {
// 	Email    string `json:"email"`
// 	Token    string `json:"token"`
// 	Password string `json:"password"`
// }

// type ForgotPasswordRequest struct {
// 	Email string `json:"email"`
// }

// type ForgotPasswordResponse struct {
// 	ResetToken string `json:"resetToken"`
// 	ErrorMsg   string `json:"Message"`
// }

// type ForgotPasswordBody struct {
// 	Email string `json:"email"`
// 	// ResetURL string `json:"resetURL"`
// }

// func (h *UserHandler) ForgotPassword(c *gin.Context) {
// 	var req GeneralRequest
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	var body ForgotPasswordBody
// 	if err := h.BindBodyToStruct(req.Body, &body); err != nil {
// 		log.Printf("Error binding body (email, resetURL) for forgot password to %s: %v, "+
// 			"please use string type for projectID, authType, userType", req.AuthType, err)
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message: fmt.Sprintf("Error binding body (credentials) to %s: %v, "+
// 					"please use string type for projectID, authType, userType", req.AuthType, err),
// 				Timestamp: time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	resetToken, err := h.userService.SendPasswordResetLink(body.Email, req.UserType, context.Background())
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to send password reset link",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusInternalServerError,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	resp := ForgotPasswordResponse{
// 		ResetToken: resetToken,
// 		ErrorMsg:   "Password reset link sent",
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    resp,
// 	})
// }

// type ResetPasswordRequest struct {
// 	ResetToken      string `json:"resetToken"`
// 	NewPassword     string `json:"newPassword"`
// 	ConfirmPassword string `json:"confirmPassword"`
// }

// func (h *UserHandler) ResetPassword(c *gin.Context) {
// 	var req GeneralRequest
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	var body ResetPasswordRequest
// 	if err := h.BindBodyToStruct(req.Body, &body); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message: fmt.Sprintf("Error binding body (token, newpassword, confirmpassword) for reset password to %s: %v, "+
// 					"please use string type for projectID, authType, userType", req.AuthType, err),
// 				Timestamp: time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if err := h.userService.ResetPassword(body.ResetToken, body.NewPassword, body.ConfirmPassword); err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to reset password",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusInternalServerError,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{Message: "Success"})
// }

// func (h *UserHandler) SingleSignOn(c *gin.Context) {
// 	// Implement single sign-on logic later
// }

// type GeneralRequestWithAuth struct {
// 	Body interface{} `json:"body"`
// }

// func (h *UserHandler) UpdateUserDetails(c *gin.Context) {
// 	var request GeneralRequest
// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    fmt.Sprintf("field: nil, message: %s", err.Error()),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if request.UserType == "" || request.ProjectID == "" || request.AuthType == "" || request.Body == nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    "field: nil, message: UserType, ProjectID, AuthType, and body are required",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	// userType, exists := c.Get(middleware.UserTypeKey)
// 	// if !exists {
// 	// 	// If the userType doesn't exist in context, handle the error
// 	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "User type not found"})
// 	// 	return
// 	// }

// 	// userTypeStr, ok := userType.(string)
// 	// if !ok {
// 	// 	// If the assertion fails, return an error
// 	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assert user type as string"})
// 	// 	return
// 	// }

// 	// Get user ID from URL parameters
// 	userID, err := strconv.Atoi(c.Param("id"))
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing user_id",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    fmt.Sprintf("field: userID, message: %s", err.Error()),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	var updateFields map[string]interface{}
// 	log.Print(updateFields)
// 	if err := h.BindBodyToStruct(request.Body, &updateFields); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message: fmt.Sprintf("field: nil, message: Error binding body to %s - %v, "+
// 					"please use string type for email, userType",
// 					request.UserType, err),
// 				Timestamp: time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if raw, ok := updateFields["updated_by"]; ok {
// 		if val, ok := raw.(float64); ok && val != 0 {
// 			updateFields["updated_by"] = int(val) // convert to int if needed later
// 		} else {
// 			authAdminID, err := utils.GetIDFromContext(c, middleware.UserIDKey)
// 			if err != nil || authAdminID == 0 {
// 				delete(updateFields, "updated_by")
// 			} else {
// 				updateFields["updated_by"] = authAdminID
// 			}
// 		}
// 	} else {
// 		// If the field doesn't exist at all
// 		authAdminID, err := utils.GetIDFromContext(c, middleware.UserIDKey)
// 		if err == nil && authAdminID != 0 {
// 			updateFields["updated_by"] = authAdminID
// 		}
// 	}

// 	// Call the service layer to update the user
// 	updatedUser, err := h.userService.UpdateUserDetails(request.UserType, updateFields, uint(userID), context.Background())
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to update user details",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusInternalServerError,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    updatedUser,
// 	})
// }

// type UpdatePasswordRequest struct {
// 	OldPassword     string `json:"oldPassword"`
// 	NewPassword     string `json:"newPassword"`
// 	ConfirmPassword string `json:"confirmPassword"`
// }

// func (h *UserHandler) UpdatePassword(c *gin.Context) {
// 	var request GeneralRequest
// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if request.UserType == "" || request.ProjectID == "" || request.AuthType == "" || request.Body == nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    "UserType, ProjectID, AuthType, and body are required",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	var body UpdatePasswordRequest
// 	if err := h.BindBodyToStruct(request.Body, &body); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid request body",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    "UserType, ProjectID, AuthType, and body are required",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	userIDStr := c.Param("id")
// 	userID, err := strconv.ParseUint(userIDStr, 10, 32) // base 10, 32 bits
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing user_id",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if err := h.userService.UpdatePassword(body.OldPassword, body.NewPassword, body.ConfirmPassword, request.UserType, uint(userID), context.Background()); err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to update password",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusInternalServerError,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{Message: "Success"})
// }

// func (h *UserHandler) DeleteUser(c *gin.Context) {
// 	userIDStr := c.Param("id")
// 	userID, err := strconv.ParseUint(userIDStr, 10, 32)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing user_id",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	authenticatedUserID, exists := c.Get(middleware.UserIDKey)
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, GeneralResponse{
// 			Message: "Unauthorized",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusUnauthorized,
// 				Message:    "Authentication is required to access this resource",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	authUserID, ok := authenticatedUserID.(uint)
// 	if !ok {
// 		c.JSON(http.StatusUnauthorized, GeneralResponse{
// 			Message: "Unauthorized",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusUnauthorized,
// 				Message:    "Invalid authenticated_user_id, authentication required",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if authUserID == uint(userID) {
// 		c.JSON(http.StatusForbidden, GeneralResponse{
// 			Message: "Failed to delete user account",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusForbidden,
// 				Message:    "You cannot delete your own user account",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	err = h.userService.DeleteUser(uint(userID))
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to delete user account",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusInternalServerError,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{Message: "Success"})
// }

// func (h *UserHandler) ActivateUser(c *gin.Context) {
// 	var response GeneralResponse
// 	defaultResponse := GeneralResponse{
// 		Message: "Failed to activate user", // Default message
// 		HttpError: &httputil.HttpError{
// 			Method:    "POST",
// 			URL:       c.Request.URL.String(),
// 			Timestamp: time.Now(),
// 		},
// 	}

// 	var request GeneralRequest
// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusBadRequest
// 		response.HttpError.Message = fmt.Sprintf("Error binding body to %s's %s: %v, please use string type for projectID, authType, userType", request.ProjectID, request.AuthType, err)

// 		c.JSON(http.StatusBadRequest, response)
// 		return
// 	}

// 	if request.UserType == "" || request.ProjectID == "" || request.AuthType == "" {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusBadRequest
// 		response.HttpError.Message = "Missing required fields. UserType, ProjectID, AuthType, Body are required"

// 		c.JSON(http.StatusBadRequest, response)
// 		return
// 	}

// 	userIDStr := c.Param("id")
// 	userID, err := strconv.ParseUint(userIDStr, 10, 32) // base 10, 32 bits
// 	if err != nil {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusBadRequest
// 		response.HttpError.Message = fmt.Sprintf("Invalid user ID: %v", err)

// 		c.JSON(http.StatusBadRequest, response)
// 		return
// 	}

// 	err = h.userService.ActivateUser(uint(userID), context.Background())
// 	if err != nil {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusNotFound
// 		response.HttpError.Message = fmt.Sprintf("Failed to activate user: %v", err)

// 		c.JSON(http.StatusUnauthorized, response)
// 		return
// 	}

// 	response = defaultResponse
// 	response.Message = "User activated successfully"
// 	response.HttpError = nil

// 	c.JSON(http.StatusOK, response)
// }

// func (h *UserHandler) GetUsersAdminOnly(c *gin.Context) {
// 	var response GeneralResponse
// 	defaultResponse := GeneralResponse{
// 		Message: "Failed to get IDs of Admin only", // Default message
// 		HttpError: &httputil.HttpError{
// 			Method:    "POST",
// 			URL:       c.Request.URL.String(),
// 			Timestamp: time.Now(),
// 		},
// 	}

// 	var request GeneralRequest
// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusBadRequest
// 		response.HttpError.Message = err.Error()

// 		c.JSON(http.StatusBadRequest, response)
// 		return
// 	}

// 	if request.UserType == "" || request.ProjectID == "" || request.AuthType == "" {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusBadRequest
// 		response.HttpError.Message = "Missing required fields. UserType, ProjectID, AuthType, Body are required"

// 		c.JSON(http.StatusBadRequest, response)
// 		return
// 	}

// 	ids, err := h.userService.GetUsersAdminOnly(context.Background())
// 	if err != nil {
// 		response = defaultResponse
// 		response.HttpError.StatusCode = http.StatusNotFound
// 		response.HttpError.Message = err.Error()

// 		c.JSON(http.StatusUnauthorized, response)
// 		return
// 	}

// 	response = defaultResponse
// 	response.Message = "Fetch admin ids Successful"
// 	response.Data = ids
// 	response.HttpError = nil

// 	c.JSON(http.StatusOK, response)
// }

// func (h *UserHandler) GetAllUsers(c *gin.Context) {
// 	var request struct {
// 		UserType  string `json:"userType"`
// 		ProjectID string `json:"projectID"`
// 		AuthType  string `json:"authType"`
// 		Body      struct {
// 			Filter string `json:"filter"`
// 			Sort   string `json:"sort"`
// 			Page   int    `json:"page"`
// 			Size   int    `json:"size"`
// 			Lite   bool   `json:"lite"`
// 		} `json:"body"`
// 	}

// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Failed: invalid or missing json input",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if request.UserType == "" || request.ProjectID == "" || request.AuthType == "" {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Failed",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    "field: user_type/project_id/auth_type, message: UserType, ProjectID, AuthType are required",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	// Pagination
// 	var page, size int
// 	if request.Body.Page <= 0 {
// 		page = 1 // default page
// 	} else {
// 		page = request.Body.Page
// 	}
// 	if request.Body.Size <= 0 {
// 		size = 10 // default size
// 	} else {
// 		size = request.Body.Size
// 	}

// 	// Sorting
// 	sortParam := request.Body.Sort
// 	sortBy := "id"
// 	sortOrder := "asc"

// 	if sortParam != "" {
// 		parts := strings.Split(sortParam, ":")
// 		if len(parts) == 2 {
// 			sortBy = parts[0]
// 			sortOrder = parts[1]
// 		} else {
// 			c.JSON(http.StatusBadRequest, GeneralResponse{
// 				Message: "Failed to sort",
// 				HttpError: &httputil.HttpError{
// 					Method:     c.Request.Method,
// 					URL:        c.Request.URL.String(),
// 					StatusCode: http.StatusBadRequest,
// 					Message:    fmt.Sprintf("field: sort, message: Invalid sort parameter format - %s", sortParam),
// 					Timestamp:  time.Now(),
// 				},
// 			})
// 			return
// 		}
// 	}

// 	if sortOrder != "asc" && sortOrder != "desc" {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: fmt.Sprintf("Invalid sort order: %s", sortOrder),
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    "field: sort, message: Invalid sort order",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	// Filters
// 	var allowedFilters []string
// 	if request.UserType == "KMSadmin" {
// 		// Allowed filters for admins
// 		allowedFilters = []string{
// 			"id", "first_name", "last_name", "department_id", "email",
// 			"mobile", "user_status", "last_login", "last_pass_change",
// 			"role_id", "card_no", "card_id", "valid_from", "valid_till",
// 			"telegram_id", "username", "created_by", "created_at", "updated_by", "updated_at", "card_id_like",
// 		}
// 	} else if request.UserType == "KMSuser" {
// 		// Allowed filters for users
// 		allowedFilters = []string{
// 			"id", "src_db", "b_user_id", "first_name", "last_name",
// 			"department_id", "email", "mobile", "user_status",
// 			"last_login", "last_pass_change", "role_id", "card_no",
// 			"card_id", "valid_from", "valid_till", "telegram_id",
// 			"created_by", "created_at", "updated_by", "updated_at", "card_id_like",
// 		}
// 	} else {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid userType",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    "field: user_type, message: Expect 'KMSuser' or 'KMSadmin'",
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 	}

// 	filters := make(map[string]string)
// 	filterParam := request.Body.Filter

// 	if filterParam != "" {
// 		filterPairs := strings.Split(filterParam, ",")
// 		for _, pair := range filterPairs {
// 			parts := strings.Split(pair, ":")
// 			if len(parts) != 2 {
// 				c.JSON(http.StatusBadRequest, GeneralResponse{
// 					Message: "Invalid filter format",
// 					HttpError: &httputil.HttpError{
// 						Method:     c.Request.Method,
// 						URL:        c.Request.URL.String(),
// 						StatusCode: http.StatusBadRequest,
// 						Message:    fmt.Sprintf("field: filter, message: Invalid filter format - %s", pair),
// 						Timestamp:  time.Now(),
// 					},
// 				})
// 				return
// 			}

// 			field := parts[0]
// 			value := parts[1]

// 			if !h.contains(allowedFilters, field) {
// 				c.JSON(http.StatusBadRequest, GeneralResponse{
// 					Message: "Invalid filter field",
// 					HttpError: &httputil.HttpError{
// 						Method:     c.Request.Method,
// 						URL:        c.Request.URL.String(),
// 						StatusCode: http.StatusBadRequest,
// 						Message:    fmt.Sprintf("field: filter, message: Invalid filter field - %s", field),
// 						Timestamp:  time.Now(),
// 					},
// 				})
// 				return
// 			}

// 			filters[field] = value
// 		}
// 	}

// 	lite := request.Body.Lite
// 	var userTypeName string
// 	if request.UserType == "KMSadmin" {
// 		userTypeName = "admin"
// 	} else {
// 		userTypeName = "user"
// 	}

// 	if lite {
// 		users, count, err := h.userService.GetUsersLite(request.UserType, c.Request.Context())
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, GeneralResponse{
// 				Message: fmt.Sprintf("Failed to get all %s", userTypeName),
// 				HttpError: &httputil.HttpError{
// 					Method:     c.Request.Method,
// 					URL:        c.Request.URL.String(),
// 					StatusCode: http.StatusInternalServerError,
// 					Message:    err.Error(),
// 					Timestamp:  time.Now(),
// 				},
// 			})
// 			return
// 		}
// 		c.JSON(http.StatusOK, GeneralResponse{
// 			Message: "Success",
// 			Data: gin.H{
// 				"users": users,
// 				"count": count,
// 			},
// 		})
// 	} else {
// 		users, count, err := h.userService.GetAllUsers(page, size, sortBy, sortOrder, filters, request.UserType, c.Request.Context())
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, GeneralResponse{
// 				Message: fmt.Sprintf("Failed to get all %s", userTypeName),
// 				HttpError: &httputil.HttpError{
// 					Method:     c.Request.Method,
// 					URL:        c.Request.URL.String(),
// 					StatusCode: http.StatusInternalServerError,
// 					Message:    err.Error(),
// 					Timestamp:  time.Now(),
// 				},
// 			})
// 			return
// 		}
// 		c.JSON(http.StatusOK, GeneralResponse{
// 			Message: "Success",
// 			Data: gin.H{
// 				"users": users,
// 				"count": count,
// 			},
// 		})
// 	}
// }

// // return [emai1, email2, email3]
// func (h *UserHandler) GetEmailsByIDs(c *gin.Context) {
// 	defaultResponse := GeneralResponse{
// 		Message: "Failed to get emails by IDs", // Default message
// 		HttpError: &httputil.HttpError{
// 			Method:    "POST",
// 			URL:       c.Request.URL.String(),
// 			Timestamp: time.Now(),
// 		},
// 	}

// 	var request GeneralRequest
// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		defaultResponse.Message = "UserType, ProjectID, AuthType, and body are required"
// 		defaultResponse.HttpError.StatusCode = http.StatusBadRequest
// 		defaultResponse.HttpError.Message = "Missing required fields"

// 		c.JSON(http.StatusBadRequest, defaultResponse)
// 		return
// 	}

// 	if request.UserType == "" || request.ProjectID == "" || request.AuthType == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "UserType, ProjectID, AuthType, and body are required"})
// 		return
// 	}

// 	if request.Body == nil {
// 		defaultResponse.Message = "Body is required"
// 		defaultResponse.HttpError.StatusCode = http.StatusBadRequest
// 		defaultResponse.HttpError.Message = "Missing 'Body' in request"

// 		c.JSON(http.StatusBadRequest, defaultResponse)
// 		return
// 	}

// 	var body []uint
// 	if err := h.BindBodyToStructEnhanced(request.Body, &body); err != nil {
// 		defaultResponse.Message = fmt.Sprintf("Error binding body to %s's %s: %v, please use string type for projectID, authType, userType", request.ProjectID, request.AuthType, err)
// 		defaultResponse.HttpError.StatusCode = http.StatusBadRequest
// 		defaultResponse.HttpError.Message = err.Error()

// 		c.JSON(http.StatusBadRequest, defaultResponse)
// 		return
// 	}

// 	emails, err := h.userService.GetEmailsByIDs(body, request.UserType, context.Background())
// 	if err != nil {
// 		defaultResponse.Message = "Failed to fetch emails by IDs"
// 		defaultResponse.HttpError.StatusCode = http.StatusInternalServerError
// 		defaultResponse.HttpError.Message = err.Error()

// 		c.JSON(http.StatusInternalServerError, defaultResponse)
// 		return
// 	}

// 	response := GeneralResponse{
// 		Message: "Success",
// 		Data:    emails,
// 	}

// 	c.JSON(http.StatusOK, response)
// }

// func (h *UserHandler) GetEmails(c *gin.Context) {
// 	var request struct {
// 		UserType  string `json:"userType"`
// 		ProjectID string `json:"projectID"`
// 		AuthType  string `json:"email"`
// 		Body      []uint `json:"body"`
// 	}

// 	if err := c.ShouldBindJSON(&request); err != nil {
// 		c.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing json input",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusBadRequest,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	emails, err := h.userService.GetEmails(request.Body, request.UserType, c.Request.Context())
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to fetch emails with usernames",
// 			HttpError: &httputil.HttpError{
// 				Method:     c.Request.Method,
// 				URL:        c.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusInternalServerError,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	c.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    emails,
// 	})
// }

// func (h *UserHandler) GetUserByMobile(ctx *gin.Context) {
// 	mobile, err := strconv.Atoi(ctx.Param("mobile"))
// 	if err != nil {
// 		ctx.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing mobile number",
// 			Data:    nil,
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				StatusCode: http.StatusBadRequest,
// 				Message:    err.Error(),
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	user, err := h.userService.GetUserByMobile(ctx.Request.Context(), mobile)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to fetch user with mobile",
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusInternalServerError,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}
// 	ctx.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    user,
// 	})
// }

// func (h *UserHandler) GetUserByMobileCard(ctx *gin.Context) {
// 	var request struct {
// 		Body struct {
// 			// Mobile uint `json:"mobile"`
// 			// CardID uint `json:"card_id"`
// 			Identifier uint `json:"identifier"`
// 		} `json:"body"`
// 	}

// 	if err := ctx.ShouldBindJSON(&request); err != nil {
// 		ctx.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing json input",
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusBadRequest,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	if request.Body.Identifier == 0 {
// 		ctx.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing identifier",
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				Message:    "field: identifier, message: Missing or invalid identifier",
// 				StatusCode: http.StatusBadRequest,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	user, _ := h.userService.GetUserByMobileCard(request.Body.Identifier)

// 	ctx.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    user,
// 	})
// }

// func (h *UserHandler) GetUsersByBUserIDs(ctx *gin.Context) {
// 	var request struct {
// 		Body struct {
// 			BUserIDs []uint `json:"b_user_id"`
// 		} `json:"body"`
// 	}

// 	if err := ctx.ShouldBindJSON(&request); err != nil {
// 		ctx.JSON(http.StatusBadRequest, GeneralResponse{
// 			Message: "Invalid or missing json input",
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusBadRequest,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	user, err := h.userService.GetUsersByBUserIDs(request.Body.BUserIDs)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to fetch users with b_user_ids",
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusInternalServerError,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	ctx.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    user,
// 	})
// }

// func (h *UserHandler) GetTelegramIDs(ctx *gin.Context) {
// 	telegramIDs, err := h.userService.GetTelegramIDs()
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, GeneralResponse{
// 			Message: "Failed to fetch all telegram_ids of admins",
// 			HttpError: &httputil.HttpError{
// 				Method:     ctx.Request.Method,
// 				URL:        ctx.Request.URL.String(),
// 				Message:    err.Error(),
// 				StatusCode: http.StatusInternalServerError,
// 				Timestamp:  time.Now(),
// 			},
// 		})
// 		return
// 	}

// 	ctx.JSON(http.StatusOK, GeneralResponse{
// 		Message: "Success",
// 		Data:    telegramIDs,
// 	})
// }
