package controller

import "user-auth/internal/services"

type Controller interface {
}

type controller struct {
	Services services.Services
}

func NewController(services services.Services) Controller {
	return &controller{
		Services: services,
	}
}
