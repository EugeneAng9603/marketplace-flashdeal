package config

import (
	"log"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	Environment       string
	DBSource          string
	Internal_API_Key1 string
	ServerAddress     string
}

const DBName_DEV = "user"
const DBName_PROD = "user_prod"

var dbNames = map[string]string{
	"dev":  DBName_DEV,
	"prod": DBName_PROD,
}

var (
	currentConfig Config
	configLock    sync.RWMutex
)

// InitConfig loads .env and JSON config and sets up a watcher for live reload
func InitConfig() {
	_ = godotenv.Load()

	env := strings.ToLower(os.Getenv("ENV"))
	if env == "" {
		env = "dev" // default fallback
	}

	viper.SetConfigName(env)
	viper.SetConfigType("json")
	viper.AddConfigPath("./internal/config/config_files")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("[InitConfig] Error reading config file: %v", err)
	}

	viper.AutomaticEnv() // pull from OS env

	loadConfigFromViper() // initial load

	// Watch for config changes
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Printf("[InitConfig] Config file changed: %s", e.Name)
		loadConfigFromViper()
	})
}

// loadConfigFromViper merges Viper values into the Config struct
func loadConfigFromViper() {
	configLock.Lock()
	defer configLock.Unlock()

	env := strings.ToLower(os.Getenv("ENV"))
	dbSource := os.Getenv("DB_SOURCE") + dbNames[env] + "?charset=utf8mb4&parseTime=True&loc=Local"

	currentConfig = Config{
		Environment:       env,
		DBSource:          dbSource,
		Internal_API_Key1: os.Getenv("INTERNAL_API_KEY1"),
		ServerAddress:     viper.GetString("server_addr"),
	}
}

// GetConfig returns a thread-safe copy of the latest config
func GetConfig() Config {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig
}
