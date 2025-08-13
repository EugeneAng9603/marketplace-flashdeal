package mockrepo

import (
	"context"
	"user-auth/internal/entities"
	"user-auth/internal/repo"
)

var _ repo.MsqlRepository = &MockMsqlRepository{}

type MockMsqlRepository struct {
	CreateUserMemberFunc   func(userType, authType string, user entities.UserInterface, ctx context.Context) (uint, error)
	GetUserByEmailFunc     func(email string, userType string, ctx context.Context) (entities.UserInterface, error)
	GetUserByIDFunc        func(id uint, userType string, ctx context.Context) (entities.UserInterface, error)
	BlacklistTokenFunc     func(tokenID string, ctx context.Context) error
	IsTokenBlacklistedFunc func(token string, ctx context.Context) (bool, error)
	UpdateUserFunc         func(user entities.UserInterface, userType string, ctx context.Context) error
}

func (m *MockMsqlRepository) CreateUserMember(userType, authType string, user entities.UserInterface, ctx context.Context) (uint, error) {
	if m.CreateUserMemberFunc != nil {
		return m.CreateUserMemberFunc(userType, authType, user, ctx)
	}
	// Default fake implementation
	return 1, nil
}

func (m *MockMsqlRepository) GetUserByEmail(email string, userType string, ctx context.Context) (entities.UserInterface, error) {
	if m.GetUserByEmailFunc != nil {
		return m.GetUserByEmailFunc(email, userType, ctx)
	}
	return &entities.UserMember{
		User: entities.User{
			Email: email,
		},
	}, nil
}
func (m *MockMsqlRepository) GetUserByID(id uint, userType string, ctx context.Context) (entities.UserInterface, error) {
	if m.GetUserByIDFunc != nil {
		return m.GetUserByIDFunc(id, userType, ctx)
	}
	return &entities.UserMember{
		User: entities.User{
			ID: id,
		},
	}, nil
}
func (m *MockMsqlRepository) BlacklistToken(tokenID string, ctx context.Context) error {
	if m.BlacklistTokenFunc != nil {
		return m.BlacklistTokenFunc(tokenID, ctx)
	}
	// Default fake implementation
	return nil
}
func (m *MockMsqlRepository) IsTokenBlacklisted(token string, ctx context.Context) (bool, error) {
	if m.IsTokenBlacklistedFunc != nil {
		return m.IsTokenBlacklistedFunc(token, ctx)
	}
	// Default fake implementation
	return false, nil
}
func (m *MockMsqlRepository) UpdateUser(user entities.UserInterface, userType string, ctx context.Context) error {
	if m.UpdateUserFunc != nil {
		return m.UpdateUserFunc(user, userType, ctx)
	}
	// Default fake implementation
	return nil
}
