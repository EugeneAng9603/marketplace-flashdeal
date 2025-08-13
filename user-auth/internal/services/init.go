package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"user-auth/internal/entities"
	"user-auth/internal/repo"
	"user-auth/internal/services/auth"
	"user-auth/internal/services/token"
	"user-auth/internal/services/validation"
	"user-auth/pkg/auth_util"
)

type Services interface {
	Login(credentials auth.LoginCredentials, loginType string, userType string, ctx context.Context) (entities.UserInterface, string, string, error)
	Register(userType, authType string, user entities.UserInterface, ctx context.Context) (uint, error)
	Logout(token string, ctx context.Context) error

	// 	RefreshToken(refreshToken string, userType string, ctx context.Context) (string, string, error)
	GetUserByID(userID uint, userType string, ctx context.Context) (entities.UserInterface, error)
	// 	GetAllUsers(page, size int, sortBy, sortOrder string, filters map[string]string, userType string, ctx context.Context) (interface{}, int, error)
	// 	GetUsersLite(userType string, ctx context.Context) (interface{}, int, error)
	// 	GetUsersAdminOnly(ctx context.Context) ([]uint, error)
	// 	GetEmailsByIDs(userIDs []uint, userType string, ctx context.Context) ([]string, error)
	// 	UpdateUserDetails(userType string, fields map[string]interface{}, userID uint, ctx context.Context) (entities.UserInterface, error)
	// 	UpdateUserFields(userType string, fields map[string]interface{}, user entities.UserInterface, ctx context.Context) error
	// 	DeleteUser(userID uint) error

	// 	GetTimeNow() (timestamp time.Time, nullDateOnly entities.NullDateOnly)
	// 	SendPasswordResetLink(email, userType string, ctx context.Context) (string, error)
	// 	ResetPassword(token, newPassword, confirmPassword string) error
	// 	UpdatePassword(oldPassword, newPassword, confirmPassword, userType string, userID uint, ctx context.Context) error
	// 	ActivateUser(userID uint, ctx context.Context) error
}

type services struct {
	mysqlRepo          repo.MsqlRepository
	emailAuthenticator auth.Authenticator
	tokenService       token.TokenService
}

func NewServices(
	mysqlRepo repo.MsqlRepository,
) Services {
	return &services{

		mysqlRepo: mysqlRepo,
	}
}

func (s *services) Login(credentials auth.LoginCredentials, loginType string, userType string, ctx context.Context) (entities.UserInterface, string, string, error) {
	var user entities.UserInterface
	var err error
	switch loginType {
	case "email":
		user, err = s.emailAuthenticator.Login(credentials, userType, ctx)
	// case "id":
	// 	return s.idAuthenticator.Login(credentials)
	// case "oauth":
	// 	return s.oauthAuthenticator.Login(credentials)
	default:
		return nil, "", "", errors.New("field: login_type, message: Unsupported login type")
	}

	if err != nil {
		return nil, "", "", err
	}

	// token generation
	accessToken, err := s.tokenService.GenerateAccessToken(user.GetID(), userType)
	if err != nil {
		return nil, "", "", fmt.Errorf("field: access_token, message: Failed to generate access token [%w]", err)
	}

	refreshToken, err := s.tokenService.GenerateRefreshToken(user.GetID(), userType)
	if err != nil {
		return nil, "", "", fmt.Errorf("field: refresh_token, message: Failed to generate refresh token [%w]", err)
	}
	sanitizedUser := auth_util.SanitizeUser(user)

	return sanitizedUser, accessToken, refreshToken, err
}

func (s *services) Register(userType, authType string, user entities.UserInterface, ctx context.Context) (uint, error) {
	var password string
	var defaultUserStatus uint8 = 1 // User status default to active

	if err := s.SetAllTime(user); err != nil {
		return 0, fmt.Errorf("field: created_by/updated_by, message: register failed due to set time failed, err is %v", err)
	}

	user.EnsureValidFromIsSet() // Set valid from to today's date if not specified

	currTime := time.Now()
	switch u := user.(type) {
	case *entities.UserMember:
		u.SetUserStatus(defaultUserStatus)

		user.SetLastPassChange(&currTime)
		password = u.Password

		if err := validation.ValidatePasswordStrength(password); err != nil {
			errorMessage := err.Error()
			return 0, fmt.Errorf("field: password, message: %v", strings.ToUpper(errorMessage[:1])+errorMessage[1:])
		}

		hashedPassword, err := validation.HashPassword(password)
		if err != nil {
			return 0, fmt.Errorf("field: password, message: %w", err)
		}
		u.SetPassword(hashedPassword)

		log.Printf("[REGISTER] %v", user)

		if err := validation.ValidateUser(user); err != nil {
			return 0, fmt.Errorf("field: nil, message: %w", err)
		}
		log.Printf("[REGISTER] %v", user)

		return s.mysqlRepo.CreateUserMember(userType, authType, user, ctx)

	default:
		return 0, errors.New("field: userType, message: unsupported user type for registration")
	}
}

func (s *services) SetAllTime(user entities.UserInterface) error {
	currTime := time.Now()
	// user.SetLastPassChange(currTime)
	// user.SetLastLogin(currTime)
	user.SetCreatedAt(currTime)
	user.SetUpdatedAt(currTime)
	return nil
}

// check token validity, if valid blacklist token.
// since we are using a custom claims and golang-jwt/jwt/v5
func (s *services) Logout(refreshToken string, ctx context.Context) error {
	_, err := s.tokenService.ValidateToken(refreshToken)
	if err != nil {
		return fmt.Errorf("field: refresh_token, message: Failed to validate token [%w]", err)
	}

	err = s.mysqlRepo.BlacklistToken(refreshToken, ctx)
	if err != nil {
		return fmt.Errorf("field: refresh_token, message: Failed to blacklist token [%w]", err)
	}

	return nil
}

// func (s *services) RefreshToken(refreshToken string, userType string, ctx context.Context) (string, string, error) {
// 	validToken, err := s.tokenService.ValidateToken(refreshToken)
// 	if err != nil {
// 		// propogate the original error msg
// 		return "", "", fmt.Errorf("field: refresh_token, message: Failed to validate token [%w]", err)
// 	}

// 	// If refresh token is valid and not blacklisted, generate a new access token
// 	// userID, err := s.tokenService.GetUserIDFromToken(validToken)
// 	claims, err := s.tokenService.GetClaimFromToken(validToken)
// 	if err != nil {
// 		return "", "", fmt.Errorf("field: refresh_token, message: Failed to retrieve claims from token [%w]", err)
// 	}

// 	// Generate a new access token
// 	newAccessToken, err := s.tokenService.GenerateAccessToken(claims.UserID, claims.RoleID, userType)
// 	if err != nil {
// 		return "", "", fmt.Errorf("field: access_token, message: Failed to generate access token [%w]", err)
// 	}

// 	// Generate a new refresh token (rotating refresh tokens)
// 	newRefreshToken, err := s.tokenService.GenerateRefreshToken(claims.UserID, claims.RoleID, userType)
// 	if err != nil {
// 		return "", "", fmt.Errorf("field: refresh_token, message: Failed to generate refresh token [%w]", err)
// 	}

// 	return newAccessToken, newRefreshToken, nil
// }

func (s *services) GetUserByID(userID uint, userType string, ctx context.Context) (entities.UserInterface, error) {
	user, err := s.mysqlRepo.GetUserByID(userID, userType, ctx)
	if err != nil {
		return nil, err
	}
	sanitizedUser := auth_util.SanitizeUser(user)

	return sanitizedUser, nil
}

// func (s *services) GetAllUsers(page, size int, sortBy, sortOrder string, filters map[string]string, userType string, ctx context.Context) (interface{}, int, error) {
// 	users, count, err := s.repo.GetAllUsers(page, size, sortBy, sortOrder, filters, userType, ctx)
// 	if err != nil {
// 		return nil, 0, err
// 	}
// 	return users, count, nil
// }

// func (s *services) GetUsersAdminOnly(ctx context.Context) ([]uint, error) {
// 	return s.repo.GetUsersAdminOnly(ctx)
// }
// func (s *services) GetUsersLite(userType string, ctx context.Context) (interface{}, int, error) {
// 	return s.repo.GetUsersLite(userType, ctx)
// }

// func (s *services) GetEmailsByIDs(userIDs []uint, userType string, ctx context.Context) ([]string, error) {
// 	emails, err := s.repo.GetEmailsByIDs(userIDs, userType, ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return emails, nil
// }

// func (s *services) DeleteUser(userID uint) error {
// 	err := s.repo.DeleteUserByID(userID)
// 	if err != nil {
// 		// Handle specific error cases
// 		if err.Error() == "user not found" {
// 			return fmt.Errorf("user with ID %d not found", userID)
// 		}
// 		return fmt.Errorf("failed to delete user: %v", err)
// 	}

// 	return nil
// }

// func (s *services) UpdateUserDetails(userType string, fields map[string]interface{}, userID uint, ctx context.Context) (entities.UserInterface, error) {
// 	var sanitizedUser entities.UserInterface
// 	currTime, _ := s.GetTimeNow()
// 	userFromDB, err := s.repo.GetUserByID(userID, userType, ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	switch userType {
// 	case "KMSadmin":
// 		kmsAdmin, ok := userFromDB.(*entities.KMSAdmin)
// 		if !ok {
// 			return nil, fmt.Errorf("field: userType, message: user is not of type KMSAdmin")
// 		}

// 		if err := s.UpdateUserFields(userType, fields, kmsAdmin, ctx); err != nil {
// 			return nil, err
// 		}

// 		if kmsAdmin.ID == 1 && kmsAdmin.UserStatus == 0 {
// 			return nil, fmt.Errorf("field: user_status, message: universal administrator account cannot be deactivated")
// 		}

// 		if kmsAdmin.ID == 521 && kmsAdmin.UserStatus == 0 {
// 			return nil, fmt.Errorf("field: user_status, message: current administrator account cannot be deactivated")
// 		}

// 		if err := s.repo.UpdateUser(kmsAdmin, userType, ctx); err != nil {
// 			return nil, err
// 		}
// 		kmsAdmin.SetUpdatedAt(currTime)
// 		sanitizedUser = auth_util.SanitizeUser(kmsAdmin)

// 	case "KMSuser":
// 		kmsUser, ok := userFromDB.(*entities.KMSUser)
// 		if !ok {
// 			return nil, fmt.Errorf("field: userType, message: user is not of type KMSUser")
// 		}

// 		if err := s.UpdateUserFields(userType, fields, kmsUser, ctx); err != nil {
// 			return nil, err
// 		}

// 		if kmsUser.ID == 1 && kmsUser.UserStatus == 0 {
// 			return nil, fmt.Errorf("field: user_status, message: universal administrator account cannot be deactivated")
// 		}

// 		if err := s.repo.UpdateUser(kmsUser, userType, ctx); err != nil {
// 			return nil, err
// 		}
// 		kmsUser.SetUpdatedAt(currTime)
// 		sanitizedUser = kmsUser
// 	default:
// 		return nil, fmt.Errorf("field: userType, message: user type %s not found", userType)
// 	}

// 	return sanitizedUser, nil
// }

// func (s *services) UpdateUserFields(userType string, fields map[string]interface{}, user entities.UserInterface, ctx context.Context) error {
// 	existing_user_id := user.GetID()

// 	// because default is float64 for number type
// 	convertToUint := func(value interface{}) (uint, error) {
// 		if v, ok := value.(float64); ok {
// 			return uint(v), nil
// 		}
// 		return 0, fmt.Errorf("field: nil, message: invalid type for uint, expected float64")
// 	}
// 	currTime, _ := s.GetTimeNow()
// 	user.SetUpdatedAt(currTime)

// 	switch userType {
// 	case "KMSadmin":
// 		kmsAdmin, ok := user.(*entities.KMSAdmin)
// 		if !ok {
// 			return fmt.Errorf("field: nil, message: invalid user type, expected KMSAdmin")
// 		}

// 		for field, value := range fields {
// 			switch field {
// 			case "first_name":
// 				kmsAdmin.FirstName = value.(string)
// 			case "last_name":
// 				kmsAdmin.LastName = value.(string)
// 			case "password":
// 				return fmt.Errorf("field: %s, message: please update password using ResetPassword or ChangePassword", field)
// 			case "telegram_id":
// 				telegramID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for TelegramID: %v", field, err)
// 				}
// 				kmsAdmin.TelegramID = telegramID
// 			case "mobile":
// 				mobileUint64, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for Mobile: %v", field, err)
// 				}
// 				// check duplication
// 				duplicate, err := s.repo.CheckFieldDuplicates(ctx, userType, field, existing_user_id, mobileUint64)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				if duplicate {
// 					return fmt.Errorf("field: %s, message: Admin with %s %v is in the database. Please check the input again",
// 						field, field, mobileUint64)
// 				}
// 				kmsAdmin.Mobile = uint64(mobileUint64)
// 			case "asset_valid_from":
// 				parsedDate, err := parseNullDateOnly(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				kmsAdmin.AssetValidFrom = parsedDate
// 			case "asset_valid_till":
// 				parsedDate, err := parseNullDateOnly(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				kmsAdmin.AssetValidTill = parsedDate
// 			case "card_id":
// 				cardID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for CardID %v", field, err)
// 				}
// 				// check duplication
// 				duplicate, err := s.repo.CheckFieldDuplicates(ctx, userType, field, existing_user_id, cardID)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				if duplicate {
// 					return fmt.Errorf("field: %s, message: Admin with %s %v is in the database. Please check the input again",
// 						field, field, cardID)
// 				}
// 				kmsAdmin.CardID = &cardID
// 			case "email":
// 				// check duplication
// 				duplicate, err := s.repo.CheckFieldDuplicates(ctx, userType, field, existing_user_id, value.(string))
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				if duplicate {
// 					return fmt.Errorf("field: %s, message: Admin with %s %v is in the database. Please check the input again",
// 						field, field, value.(string))
// 				}
// 				kmsAdmin.Email = value.(string)
// 			case "card_no":
// 				kmsAdmin.CardNo = value.(string)
// 			case "valid_from":
// 				parsedDate, err := parseNullDateOnly(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				kmsAdmin.ValidFrom = parsedDate
// 			case "valid_till":
// 				parsedDate, err := parseNullDateOnly(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				kmsAdmin.ValidTill = parsedDate
// 			case "role_id":
// 				roleID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for RoleID %v", field, err)
// 				}
// 				kmsAdmin.RoleID = roleID
// 			case "department_id":
// 				departmentID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for DepartmentID: %v", field, err)
// 				}
// 				kmsAdmin.DepartmentID = departmentID
// 			case "user_status":
// 				userStatus, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for UserStatus: %v", field, err)
// 				}
// 				kmsAdmin.UserStatus = uint8(userStatus)
// 			case "username":
// 				kmsAdmin.Username = value.(string)
// 			case "updated_by":
// 				kmsAdmin.UpdatedBy = uint(value.(int))
// 			default:
// 				return fmt.Errorf("field: %s, unknown field %s for KMSAdmin", field, field)
// 			}
// 		}

// 	case "KMSuser":
// 		kmsUser, ok := user.(*entities.KMSUser)
// 		if !ok {
// 			return fmt.Errorf("field: nil, message: invalid user type, expected KMSUser")
// 		}

// 		for field, value := range fields {
// 			switch field {
// 			case "first_name":
// 				kmsUser.FirstName = value.(string)
// 			case "last_name":
// 				kmsUser.LastName = value.(string)
// 			case "telegram_id":
// 				telegramID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for TelegramID %v", field, err)
// 				}
// 				kmsUser.TelegramID = telegramID
// 			case "mobile":
// 				mobileUint64, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for Mobile %v", field, err)
// 				}
// 				// check duplication
// 				duplicate, err := s.repo.CheckFieldDuplicates(ctx, userType, field, existing_user_id, mobileUint64)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				if duplicate {
// 					return fmt.Errorf("field: %s, message: User with %s %v is in the database. Please check the input again",
// 						field, field, mobileUint64)
// 				}
// 				kmsUser.Mobile = uint64(mobileUint64)
// 			case "card_id":
// 				cardID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for CardID %v", field, err)
// 				}
// 				// check duplication
// 				duplicate, err := s.repo.CheckFieldDuplicates(ctx, userType, field, existing_user_id, cardID)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				if duplicate {
// 					return fmt.Errorf("field: %s, message: User with %s %v is in the database. Please check the input again",
// 						field, field, cardID)
// 				}
// 				kmsUser.CardID = &cardID
// 			case "email":
// 				kmsUser.Email = value.(string)
// 			case "b_user_id":
// 				if v, ok := value.(float64); ok {
// 					parsedBUserID := uint(v)
// 					kmsUser.BUserID = &parsedBUserID
// 				} else if v, ok := value.(int); ok {
// 					parsedBUserID := uint(v)
// 					kmsUser.BUserID = &parsedBUserID
// 				} else {
// 					return fmt.Errorf("field: %s, message: invalid type for BUserID %T", field, value)
// 				}
// 			case "card_no":
// 				kmsUser.CardNo = value.(string)
// 			case "valid_from":
// 				parsedDate, err := parseNullDateOnly(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				kmsUser.ValidFrom = parsedDate
// 			case "valid_till":
// 				parsedDate, err := parseNullDateOnly(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: %w", field, err)
// 				}
// 				kmsUser.ValidTill = parsedDate
// 			case "role_id":
// 				roleID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for RoleID %v", field, err)
// 				}
// 				kmsUser.RoleID = roleID
// 			case "department_id":
// 				departmentID, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for DepartmentID %v", field, err)
// 				}
// 				kmsUser.DepartmentID = departmentID
// 			case "user_status":
// 				userStatus, err := convertToUint(value)
// 				if err != nil {
// 					return fmt.Errorf("field: %s, message: invalid type for UserStatus %v", field, err)
// 				}
// 				kmsUser.UserStatus = uint8(userStatus)
// 			case "updated_by":
// 				kmsUser.UpdatedBy = uint(value.(int))
// 			default:
// 				return fmt.Errorf("field: %s, message: unknown field %s for KMSUser", field, field)
// 			}
// 		}

// 	default:
// 		return fmt.Errorf("field: nil, message: unsupported user type %s", userType)
// 	}
// 	return nil
// }

// func (s *services) GetTimeNow() (timestamp time.Time, nullDateOnly entities.NullDateOnly) {
// 	loc, err := time.LoadLocation("Asia/Singapore")
// 	if err != nil {
// 		loc = time.UTC
// 	}
// 	currentTime := time.Now().In(loc)

// 	dateOnly := entities.DateOnly(currentTime)

// 	// Set the NullDateOnly to valid
// 	nullDateOnly = entities.NullDateOnly{
// 		Date:  dateOnly,
// 		Valid: true,
// 	}

// 	return currentTime, nullDateOnly
// }

// func (s *services) SendPasswordResetLink(email, userType string, ctx context.Context) (string, error) {
// 	config := config.LoadConfig()
// 	resetURL := config.ResetPasswordURL + "/"

// 	// Step 1: Find the user by email
// 	user, err := s.repo.GetUserByEmail(email, userType, ctx)
// 	if err != nil {
// 		return "", fmt.Errorf("field: email, message: Failed to fetch user with email provided [%w]", err)
// 	}

// 	// Step 2: Generate a unique reset token
// 	resetToken := uuid.New().String()

// 	// Step 3: Store the token with an expiration date (e.g., 1 hour)
// 	err = s.repo.SavePasswordResetToken(user.GetID(), resetToken, time.Now().Add(1*time.Hour))
// 	if err != nil {
// 		return "", errors.New("field: reset_token, message: Failed to store reset token")
// 	}

// 	// Step 4: Send email using KMS email domain
// 	// err = utils.SendCAGEmail(email, "KMS Admin Password Reset", "", map[string]string{"reset": resetURL + resetToken})
// 	err = utils.SendEmailAlt(email, nil, "KMS Admin Password Reset", "", map[string]string{"reset": resetURL + resetToken})
// 	if err != nil {
// 		return "", err
// 	}
// 	return resetToken, nil
// }

// func (s *services) ResetPassword(token, newPassword, confirmPassword string) error {
// 	// Step 0: Find the reset token in the database
// 	resetToken, err := s.repo.GetResetToken(token)
// 	if err != nil {
// 		return errors.New("field: reset_token, message: Invalid or expired reset token")
// 	}
// 	// Step 1: Check if the token is expired
// 	if resetToken.Expiration.Before(time.Now()) {
// 		return errors.New("field: reset_token, message: Reset token expired")
// 	}

// 	// Step 2: Validate new and confirm password
// 	if err := validation.ValidatePasswordStrength(newPassword); err != nil {
// 		return fmt.Errorf("field: new_password, message: Password does not meet password strength requirements [%v]", err)
// 	}
// 	if newPassword != confirmPassword {
// 		return errors.New("field: confirm_password, message: Confirm password does not match new password")
// 	}
// 	// log.Printf("token is: %v, time now is: %v", resetToken, time.Now())

// 	// Step 3: Hash the new password
// 	hashedPassword, err := validation.HashPassword(newPassword)
// 	if err != nil {
// 		return fmt.Errorf("field: new_password, message: Failed to hash password [%w]", err)
// 	}

// 	// Step 4: Update the user's password
// 	currTime, _ := s.GetTimeNow()
// 	err = s.repo.UpdateUserPassword(resetToken.UserID, hashedPassword, currTime)
// 	if err != nil {
// 		return fmt.Errorf("field: new_password, message: Failed to update password [%w]", err)
// 	}

// 	// Step 5: Delete the token after use
// 	err = s.repo.DeleteResetToken(token)
// 	if err != nil {
// 		return errors.New("field: reset_token, message: Failed to delete reset token")
// 	}

// 	return nil
// }

// func (s *services) UpdatePassword(oldPassword, newPassword, confirmPassword, userType string, userID uint, ctx context.Context) error {
// 	// validate old password first
// 	if err := s.emailAuthenticator.VerifyPassword(oldPassword, userType, userID, ctx); err != nil {
// 		return err
// 	}
// 	// validate new password first
// 	if err := validation.ValidatePasswordStrength(newPassword); err != nil {
// 		return fmt.Errorf("field: new_password, message: Password is not strong [%v]", err)
// 	}
// 	if newPassword != confirmPassword {
// 		return errors.New("field: confirm_password, message: Confirm password does not match new password")
// 	}
// 	// hash password
// 	hashedPassword, err := validation.HashPassword(newPassword)
// 	if err != nil {
// 		return fmt.Errorf("field: new_password, message: Failed to hash password [%v]", err)
// 	}
// 	// update
// 	currTime, _ := s.GetTimeNow()
// 	if err := s.repo.UpdateUserPassword(userID, hashedPassword, currTime); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (s *services) ActivateUser(userID uint, ctx context.Context) error {
// 	return s.repo.ActivateUser(userID, ctx)
// }

// func parseNullDateOnly(value interface{}) (entities.NullDateOnly, error) {
// 	if str, ok := value.(string); ok {
// 		parsedDate, err := time.Parse("2006-01-02", str)
// 		if err != nil {
// 			return entities.NullDateOnly{}, fmt.Errorf("failed to parse date: %v", err)
// 		}
// 		return entities.NullDateOnly{Date: entities.DateOnly(parsedDate), Valid: true}, nil
// 	}

// 	return entities.NullDateOnly{}, fmt.Errorf("expected string for NullDateOnly, got %T", value)
// }

// func (s *services) DeleteKMSUserAdmin(ctx context.Context, user_type string, id uint, current_user_id uint, current_role_id uint) error {
// 	if id == 0 {
// 		return errors.New("invalid or missing user_id")
// 	}

// 	if id == 1 {
// 		return fmt.Errorf("failed to delete administrator account")
// 	}

// 	if current_user_id == id && current_role_id <= 3 {
// 		return fmt.Errorf("failed to delete own account")
// 	}

// 	switch user_type {
// 	case "KMSadmin":
// 		err := s.repo.DeleteKMSAdmin(ctx, id)
// 		if err != nil {
// 			return fmt.Errorf("failed to delete %s with id %d: %w", user_type, id, err)
// 		}
// 	case "KMSuser":
// 		err := s.repo.DeleteKMSUser(ctx, id)
// 		if err != nil {
// 			return fmt.Errorf("failed to delete %s with id %d: %w", user_type, id, err)
// 		}
// 	default:
// 		return fmt.Errorf("invalid user_type: %s, expecting `KMSadmin` or `KMSuser`", user_type)
// 	}
// 	return nil
// }

// func (s *services) GetDeleteLogs(ctx context.Context, page, size int, sortBy, sortOrder string, filters map[string]string) (*[]entities.DeleteLog, int, error) {
// 	return s.repo.GetDeleteLogs(ctx, page, size, sortBy, sortOrder, filters)
// }

// func (s *services) GetEmails(user_ids []uint, user_type string, ctx context.Context) ([]map[string]string, error) {
// 	if len(user_ids) == 0 {
// 		return nil, fmt.Errorf("invalid or missing user_ids")
// 	}
// 	return s.repo.GetEmails(user_ids, user_type, ctx)
// }

// func (s *services) GetUserByMobile(ctx context.Context, mobile int) (*entities.KMSUserResponse, error) {
// 	if mobile == 0 {
// 		return nil, fmt.Errorf("missing mobile number")
// 	}
// 	return s.repo.GetUserByMobile(ctx, mobile)
// }

// func (s *services) GetUserByMobileCard(identifier uint) (map[string]interface{}, error) {
// 	if identifier == 0 {
// 		return nil, fmt.Errorf("field: identifier, message: Missing or invalid identifier")
// 	}
// 	return s.repo.GetUserByMobileCard(identifier)
// }

// func (s *services) GetUsersByBUserIDs(bUserIDs []uint) (*[]entities.KMSUserLite, error) {
// 	if len(bUserIDs) == 0 {
// 		return nil, fmt.Errorf("no b_user_id provided")
// 	}
// 	return s.repo.GetUsersByBUserIDs(bUserIDs)
// }

// func (s *services) GetTelegramIDs() ([]uint, error) {
// 	return s.repo.GetTelegramIDs()
// }

// func (s *services) GetAllUsersV2(userType string, params entities.QueryParam) (any, uint, error) {
// 	switch userType {
// 	case "KMSuser":
// 		return s.repo.GetAllUsersV2(params)
// 	case "KMSadmin":
// 		return s.repo.GetAllAdminsV2(params)
// 	default:
// 		return nil, 0, fmt.Errorf("invalid user type: %s", userType)
// 	}
// }
