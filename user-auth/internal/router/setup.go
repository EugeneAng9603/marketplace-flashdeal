package router

import (
	"user-auth/internal/controller"
	"user-auth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRouter(r *gin.Engine, hand controller.Controller, apiKey string, accessTokenSecret string) {
	r.Use(middleware.CORSMiddleware())
	PublicRoutes(r, hand)
	ProtectedRoutes(r, hand, apiKey, accessTokenSecret)
}

func PublicRoutes(r *gin.Engine, hand controller.Controller) {
	user := r.Group("/api/v1")
	{
		user.POST("/login", hand.Login)
		user.POST("/register", hand.Register)
		// kms.POST("/forgot-password", hand.ForgotPassword)
		// kms.POST("/reset-password", hand.ResetPassword)
		// kms.GET("/logs", hand.GetDeleteLogs)
		// kms.POST("/emails", hand.GetEmails)
		// kms.POST("/activateuser/:id", hand.ActivateUser)
		// kms.GET("/user-mobile/:mobile", hand.GetUserByMobile)
		// kms.POST("/public/user", hand.GetUserByMobileCard)
		// kms.GET("/public/departments", hand.GetDepartments)
	}
}

func ProtectedRoutes(r *gin.Engine, hand controller.Controller, apiKey string, accessTokenSecret string) {
	userProtected := r.Group("/api/v1")
	userProtected.Use(middleware.JWTAuthMiddleware(accessTokenSecret, apiKey))
	{
		userProtected.POST("/user/:id", hand.GetUserByID)
		// kmsProtected.POST("/refresh", hand.RefreshToken)
		userProtected.POST("/logout", hand.Logout)
		// kmsProtected.PATCH("/update/:id", hand.UpdateUserDetails)
		// kmsProtected.DELETE("/user/:id", hand.DeleteUser)
		// kmsProtected.PUT("/password/:id", hand.UpdatePassword)
		// kmsProtected.POST("/users", hand.GetAllUsers)
		// kmsProtected.POST("/users-emails", hand.GetEmailsByIDs)
		// kmsProtected.POST("/users/adminonly", hand.GetUsersAdminOnly)
		// kmsProtected.POST("/users/biostar", hand.GetUsersByBUserIDs)
		// kmsProtected.GET("/admins/telegram", hand.GetTelegramIDs)

	}
}
