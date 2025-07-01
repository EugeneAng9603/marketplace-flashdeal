package repo

import (
	"gorm.io/gorm"
)

type MsqlRepository interface {
}

type mysqlRepo struct {
	db *gorm.DB
}

func NewMySQLRepo(db *gorm.DB) MsqlRepository {
	return &mysqlRepo{
		db: db,
	}
}
