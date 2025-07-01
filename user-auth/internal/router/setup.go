package router

import (
	"user-auth/internal/controller"

	"github.com/gin-gonic/gin"
)

func SetupRouter(r *gin.Engine, ctrl controller.Controller, apiKey string) {
	// r.Use(middleware.Auth(apiKey))
	// r.POST("/v1/process", ctrl.ProcessData)
}
