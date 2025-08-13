package db

import (
	"database/sql"
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func InitDB(dbSource string) *gorm.DB {
	logPrefix := "[InitDB]"
	gormDB, sqlDB, err := OpenMySQLDB(dbSource)
	if err != nil {
		log.Printf("%s[Dsn: %s][Error opening MySQL database: %v]", logPrefix, dbSource, err)
		return nil
	}
	SetPoolingOptions(sqlDB)

	log.Printf("%s[Dsn: %s][Connected to database(s)]\n", logPrefix, dbSource)
	return gormDB
}

func OpenMySQLDB(dbSource string) (*gorm.DB, *sql.DB, error) {
	logPrefix := "[OpenMySQLDB]"
	const maxRetry = 3
	var err error
	var db *gorm.DB

	for retry := range maxRetry {
		db, err = gorm.Open(mysql.Open(dbSource), &gorm.Config{Logger: logger.Default.LogMode(logger.Info)})
		if err == nil {
			break
		}
		log.Printf("%s[Attempt: %d/%d][Failed to connect to MySQL: %v]", logPrefix, retry+1, maxRetry, err)
		time.Sleep(3 * time.Second)
	}
	if db == nil {
		log.Printf("%s[Failed to connect to database: %v]", logPrefix, err)
		return nil, nil, err
	}

	var sqlDB *sql.DB
	for retry := range maxRetry {
		sqlDB, err = db.DB()
		if err == nil {
			if err = sqlDB.Ping(); err == nil {
				break
			}
		}
		log.Printf("%s[Attempt: %d/%d][Failed to ping sql.DB: %v]", logPrefix, retry+1, maxRetry, err)
		time.Sleep(3 * time.Second)
	}
	if sqlDB == nil {
		log.Printf("%s[Failed to get sql.DB from GORM: %v]", logPrefix, err)
		return nil, nil, err
	}

	return db, sqlDB, nil
}

func SetPoolingOptions(sqlDB *sql.DB) {
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
}
