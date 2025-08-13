package cmd

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"stock/internal/config"
	"stock/internal/controller"
	"stock/internal/db"
	"stock/internal/repo"
	"stock/internal/services"
	"syscall"
)

func Start() {
	logPrefix := "[Start]"
	config.InitConfig()
	cfg := config.GetConfig()
	// Initialize databases
	fmt.Printf("config is %+v\n", cfg)
	mysqlDB := db.InitDB(cfg.DBSource)
	mysqlRepo := repo.NewMySQLRepo(mysqlDB)
	// Initialize service and controller layer
	svc := services.NewServices(mysqlRepo)
	ctrl := controller.NewController(svc)

	// Handle graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	log.Printf("%s[Service started successfully]", logPrefix)
	// Run HTTP server
	if err := RunServer(ctx, cfg.ServerAddress, ctrl, cfg.Internal_API_Key1); err != nil {
		log.Fatalf("%s[Server exited with error: %v]", logPrefix, err)
	}

	log.Printf("%s[Application shut down successfully.]", logPrefix)
}
