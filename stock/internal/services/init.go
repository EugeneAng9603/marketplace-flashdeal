package services

import "user-auth/internal/repo"

type Services interface {
}

type services struct {
	MysqlRepo repo.MsqlRepository
}

func NewServices(
	mysqlRepo repo.MsqlRepository,
) Services {
	return &services{

		MysqlRepo: mysqlRepo,
	}
}
