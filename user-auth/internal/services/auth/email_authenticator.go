package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
	"user-auth/internal/entities"
	"user-auth/internal/repo"
	"user-auth/internal/services/validation"
)

type EmailAuthenticator struct {
	repo repo.MsqlRepository
}

func NewEmailAuthenticator(repo repo.MsqlRepository) Authenticator {
	return &EmailAuthenticator{repo: repo}
}

func (ea *EmailAuthenticator) Login(credentials LoginCredentials, userType string, ctx context.Context) (entities.UserInterface, error) {
	if credentials.Email == "" {
		return nil, errors.New("field: email, message: Email is required")
	}
	if credentials.Password == "" {
		return nil, errors.New("field: password, message: Password is required")
	}
	user, err := ea.repo.GetUserByEmail(credentials.Email, userType, ctx)
	if user == nil {
		return nil, fmt.Errorf("field: email, message: User not found with email provided")
	}
	if user.GetUserStatus() == 0 {
		return nil, errors.New("field: email, message: Your account is deactivated, please contact Administrator (Suhaimi) to activate your account")
	}
	if err != nil {
		// log.Printf("err is : %v", err)
		return nil, errors.New("field: email, message: Failed to fetch user with email provided")
	}

	switch userType {
	case "KMSadmin":
		if !validation.ComparePasswords(user.(*entities.UserMember).GetPassword(), credentials.Password) {
			return nil, errors.New("field: password, message: Invalid email or password")
		}
	// case "LorawanAdmin":
	// 	if !validation.ComparePasswords(user.(*entities.LorawanAdmin).GetPassword(), credentials.Password) {
	// 		return nil, errors.New("invalid lorawan email or password")
	// 	}
	default:
		return nil, errors.New("field: user_type, message: Invalid password of unknown project")

	}
	// update last login
	currTime := ea.GetTimeNow()
	user.SetLastLogin(&currTime)
	// user.SetUpdatedAt(currTime)
	err = ea.repo.UpdateUser(user, userType, ctx)
	if err != nil {
		log.Printf("field: last_login, message: Failed to update user last login [%v]", err)
	}

	return user, nil
}

func (ea *EmailAuthenticator) GetTimeNow() time.Time {
	loc, _ := time.LoadLocation("Asia/Singapore")
	// if err != nil {
	// 	loc = time.UTC
	// }
	return time.Now().In(loc)
}

func (ea *EmailAuthenticator) VerifyPassword(plainPassword, userType string, userID uint, ctx context.Context) error {
	user, err := ea.repo.GetUserByID(userID, userType, ctx)
	if err != nil {
		return errors.New("field: user_id, message: Error getting user by id")
	}

	switch userType {
	// case "LorawanAdmin":
	// 	if !validation.ComparePasswords(user.(*entities.LorawanAdmin).GetPassword(), plainPassword) {
	// 		return errors.New("invalid password")
	// 	}
	case "KMSadmin":
		if !validation.ComparePasswords(user.(*entities.UserMember).GetPassword(), plainPassword) {
			return fmt.Errorf("field: old_password, message: The old password provided is incorrect. Please try again")
		}
	default:
		return errors.New("field: user_type, message: Invalid password of unknown project")
	}

	return nil
}
