package repo

import (
	"context"
	"fmt"
	"strings"
	"time"
	"user-auth/internal/entities"

	"gorm.io/gorm"
)

type MsqlRepository interface {
	CreateUserMember(userType, authType string, user entities.UserInterface, ctx context.Context) (uint, error)
	GetUserByEmail(email string, userType string, ctx context.Context) (entities.UserInterface, error)
	GetUserByID(id uint, userType string, ctx context.Context) (entities.UserInterface, error)
	// GetAllUsers(page, size int, sortBy, sortOrder string, filters map[string]string, userType string, ctx context.Context) (interface{}, int, error)
	BlacklistToken(tokenID string, ctx context.Context) error
	IsTokenBlacklisted(token string, ctx context.Context) (bool, error)
	UpdateUser(user entities.UserInterface, userType string, ctx context.Context) error
	// CleanupBlacklistedTokens(ctx context.Context) error
	// GetResetToken(token string) (entities.PasswordResetToken, error)
	// SavePasswordResetToken(userID uint, token string, expiration time.Time) error
	// UpdateUserPassword(userID uint, newPassword string, currTime time.Time) error
	// DeleteResetToken(token string) error
	// DeleteUserByID(id uint) error
	// GetUsersFromTable(page, size int, sortBy, sortOrder string, filters map[string]string, tableName string, users interface{}, ctx context.Context) (int, error)
	// GetUsersAdminOnly(ctx context.Context) ([]uint, error)
	// ActivateUser(userID uint, ctx context.Context) error

	// CheckFieldDuplicates(ctx context.Context, user_type string, field string, user_id uint, value interface{}) (bool, error)
	// GetDeleteLogs(ctx context.Context, page, size int, sortBy, sortOrder string, filters map[string]string) (*[]entities.DeleteLog, int, error)
	// GetEmails(user_ids []uint, user_type string, ctx context.Context) ([]map[string]string, error)
	// GetUserByMobile(ctx context.Context, mobile int) (*entities.KMSUserResponse, error)
	// GetUserByMobileCard(identifier uint) (map[string]interface{}, error)
	// GetUsersByBUserIDs(bUserIDs []uint) (*[]entities.KMSUserLite, error)
	// GetTelegramIDs() ([]uint, error)

	// Latest update(s)
	// GetAllUsersV2(params entities.QueryParam) (any, uint, error)
	// GetAllAdminsV2(params entities.QueryParam) (any, uint, error)
}

type mysqlRepo struct {
	db *gorm.DB
}

func NewMySQLRepo(db *gorm.DB) MsqlRepository {
	return &mysqlRepo{
		db: db,
	}
}

var UserTableName = "user_member"

func (r *mysqlRepo) CreateUserMember(
	userType, authType string,
	user entities.UserInterface,
	ctx context.Context,
) (uint, error) {

	switch u := user.(type) {
	case *entities.UserMember:
		if err := r.db.WithContext(ctx).
			Table(UserTableName).
			Create(&u).Error; err != nil {
			if strings.Contains(err.Error(), "Duplicate entry") {
				switch {
				case strings.Contains(err.Error(), "card_id"):
					// Duplicate user card_id
					return 0, fmt.Errorf("field: card_id, message: User with duplicated card_id is in the database. Please check the input again")
				case strings.Contains(err.Error(), "mobile"):
					// Duplicate user mobile
					return 0, fmt.Errorf("field: mobile, message: User with duplicated mobile is in the database. Please check the input again")
				}
			}
			// Other errors
			return 0, fmt.Errorf("field: nil, message: %w", err)
		}
		return u.ID, nil

	default:
		return 0, fmt.Errorf("field: user_type, message: Unsupported user type for registration %T", u)
	}
}

func (r *mysqlRepo) GetUserByEmail(email string, userType string, ctx context.Context) (entities.UserInterface, error) {
	var userInterface entities.UserInterface
	var tableName string

	switch userType {
	case "KMSuser":
		var userUser entities.UserMember
		userInterface = &userUser
		tableName = UserTableName
	default:
		return nil, fmt.Errorf("user type %s not found to get user by email", userType)
	}

	err := r.getUserFromTableByEmail(tableName, userInterface, ctx, email)
	if err != nil {
		// Handle specific errors like not found ...
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user with email not found")
		}
		return nil, err
	}

	return userInterface, nil
}

func (r *mysqlRepo) GetUserByID(ID uint, userType string, ctx context.Context) (entities.UserInterface, error) {
	var userInterface entities.UserInterface
	var tableName string

	switch userType {
	case "user_member":
		var userUser entities.UserMember
		userInterface = &userUser
		tableName = UserTableName
	default:
		return nil, fmt.Errorf("field: user_type, message: Invalid user type")
	}

	err := r.getUserFromTableByID(tableName, userInterface, ctx, ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("field: user_id, message: Failed to get user by user ID provided [%v]", err)
		}
		return nil, err
	}
	return userInterface, nil
}

// func (r *mysqlRepo) GetEmailsByIDs(userIDs []uint, userType string, ctx context.Context) ([]string, error) {
// 	var emails []string
// 	var tableName string

// 	switch userType {
// 	case "KMSadmin":
// 		tableName = AdminTableName
// 		err := r.db.Table(tableName).WithContext(ctx).Where("id IN ?", userIDs).Pluck("email", &emails).Error
// 		if err != nil {
// 			return nil, fmt.Errorf("error fetching emails for KMSadmins: %w", err)
// 		}
// 	case "KMSuser":
// 		tableName = UserTableName
// 		err := r.db.Table(tableName).WithContext(ctx).Where("id IN ?", userIDs).Pluck("email", &emails).Error
// 		if err != nil {
// 			return nil, fmt.Errorf("error fetching emails for KMSusers: %w", err)
// 		}
// 	default:
// 		return nil, fmt.Errorf("user type of %s not found", userType)
// 	}

// 	// a set
// 	emailMap := make(map[string]struct{})
// 	var uniqueEmails []string
// 	for _, email := range emails {
// 		if _, exists := emailMap[email]; !exists {
// 			emailMap[email] = struct{}{}
// 			uniqueEmails = append(uniqueEmails, email)
// 		}
// 	}

// 	return uniqueEmails, nil
// }

func (r *mysqlRepo) getUserFromTableByEmail(tableName string, userInterface interface{}, ctx context.Context, email string) error {
	if r.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	return r.db.Table(tableName).WithContext(ctx).Where("email = ?", email).First(userInterface).Error
}
func (r *mysqlRepo) getUserFromTableByID(tableName string, userInterface interface{}, ctx context.Context, ID uint) error {
	if r.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	if err := r.db.Preload("Department").
		Preload("Role").
		Table(tableName).
		WithContext(ctx).
		Where("id = ?", ID).
		First(userInterface).Error; err != nil {
		return fmt.Errorf("failed to fetch user: %w", err)
	}
	return nil
}

type BlacklistedToken struct {
	TokenID       string    `gorm:"column:token_id;primaryKey"`
	InvalidatedAt time.Time `gorm:"column:invalidated_at"`
	ExpiresAt     time.Time `gorm:"column:expires_at"`
}

func (r *mysqlRepo) BlacklistToken(tokenID string, ctx context.Context) error {
	blacklistedToken := BlacklistedToken{
		TokenID:       tokenID,
		InvalidatedAt: time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour * 24),
	}
	return r.db.WithContext(ctx).Create(&blacklistedToken).Error
}

func (r *mysqlRepo) IsTokenBlacklisted(token string, ctx context.Context) (bool, error) {
	var blacklisted BlacklistedToken
	err := r.db.WithContext(ctx).Where("token_id = ?", token).First(&blacklisted).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return false, err
	}
	return blacklisted.TokenID != "", nil
}

// // Update user v2
func (r *mysqlRepo) UpdateUser(user entities.UserInterface, userType string, ctx context.Context) error {
	if user == nil {
		return fmt.Errorf("invalid or missing user details")
	}

	// Determine table name based on user type
	var tableName string
	switch userType {
	case "KMSuser":
		tableName = UserTableName
	default:
		return fmt.Errorf("invalid user type: %s", userType)
	}

	// Start database transaction
	tx := r.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	// Save user details
	query := tx.Table(tableName).Where("id = ?", user.GetID())
	if user.GetID() == 1 {
		query = query.Omit("user_status")
	}

	if err := query.Omit("created_at", "created_by", "department_id",
		"last_activity_indicated_at", "last_reminder_sent_at", "user_inactivated_at").
		Save(user).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update user with ID %d: %w", user.GetID(), err)
	}

	// Update biostar user if necessary
	if userType == "user_member" || tableName == UserTableName {

		// Fetch user information in KMS
		var u entities.UserMember
		if err := tx.Table(tableName).
			First(&u, user.GetID()).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to fetch existing KMS user: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// func (r *mysqlRepo) CleanupBlacklistedTokens(ctx context.Context) error {
// 	return r.db.WithContext(ctx).
// 		Where("expires_at < ?", time.Now()).
// 		Delete(&BlacklistedToken{}).Error
// }

// // func (r *mysqlRepo) DeleteUserByID(id uint) error {
// // 	result := r.db.Table("kms_admin").Where("id = ?", id).Delete(&entities.LorawanAdmin{})

// // 	// Check if any rows were affected like user found and deleted
// // 	if result.RowsAffected == 0 {
// // 		return fmt.Errorf("user with ID %d not found", id)
// // 	}

// // 	if result.Error != nil {
// // 		return fmt.Errorf("failed to delete user: %v", result.Error)
// // 	}

// // 	return nil
// // }

// func (r *mysqlRepo) GetResetToken(token string) (entities.PasswordResetToken, error) {
// 	var resetToken entities.PasswordResetToken
// 	if err := r.db.Table("kms_password_reset_tokens").Where("token = ?", token).First(&resetToken).Error; err != nil {
// 		return entities.PasswordResetToken{}, err
// 	}
// 	return resetToken, nil
// }

// func (r *mysqlRepo) SavePasswordResetToken(userID uint, token string, expiration time.Time) error {
// 	resetToken := entities.PasswordResetToken{
// 		UserID:     userID,
// 		Token:      token,
// 		Expiration: expiration,
// 	}
// 	return r.db.Table("kms_password_reset_tokens").Create(&resetToken).Error
// }

// func (r *mysqlRepo) UpdateUserPassword(userID uint, newPassword string, currTime time.Time) error {
// 	if err := r.db.Table(AdminTableName).
// 		Where("id = ?", userID).
// 		Updates(map[string]interface{}{
// 			"password":         newPassword,
// 			"last_pass_change": currTime,
// 			"updated_at":       currTime,
// 		}).Error; err != nil {
// 		return err
// 	}
// 	return nil
// }

// // delete a reset token after it's used.
// func (r *mysqlRepo) DeleteResetToken(token string) error {
// 	return r.db.Table("kms_password_reset_tokens").Where("token = ?", token).Delete(&entities.PasswordResetToken{}).Error
// }

// func (r *mysqlRepo) GetUsersAdminOnly(ctx context.Context) ([]uint, error) {
// 	var ids []uint
// 	var users []entities.KMSAdmin
// 	err := r.db.Table(AdminTableName).Where("role_id = ?", 1).Find(&users).Error
// 	if err != nil {
// 		return nil, err
// 	}

// 	for _, user := range users {
// 		ids = append(ids, user.GetID())
// 	}
// 	return ids, nil
// }

// func (r *mysqlRepo) GetAllUsers(
// 	page, size int,
// 	sortBy, sortOrder string,
// 	filters map[string]string,
// 	userType string, ctx context.Context,
// ) (interface{}, int, error) {

// 	var users []entities.UserInterface
// 	var specificUsers interface{}
// 	var tableName string

// 	switch userType {
// 	case "KMSadmin":
// 		specificUsers = []*entities.KMSAdmin{}
// 		tableName = AdminTableName
// 	case "KMSuser":
// 		tableName = UserTableName
// 		specificUsers = []*entities.KMSUser{}
// 	default:
// 		return nil, 0, errors.New("field: user_type, message: Invalid user type")
// 	}

// 	count, err := r.GetUsersFromTable(page, size, sortBy, sortOrder, filters, tableName, &specificUsers, ctx)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	switch v := specificUsers.(type) {
// 	case []*entities.KMSAdmin:
// 		for _, user := range v {
// 			sanitized_user := auth_util.SanitizeUser(user)
// 			users = append(users, sanitized_user)
// 		}
// 	case []*entities.KMSUser:
// 		for _, user := range v {
// 			users = append(users, user)
// 		}
// 	}

// 	if userType == "KMSuser" {
// 		var responses []entities.KMSUserResponse
// 		for _, user := range users {
// 			var department *entities.Department
// 			var role *entities.Role
// 			var creator, updator *entities.KMSAdmin
// 			var err error

// 			if user.GetDepartmentID() != 0 {
// 				err = r.db.Model(&entities.Department{}).
// 					Where("id = ?", user.GetDepartmentID()).
// 					First(&department).Error
// 				if err != nil || department == nil {
// 					log.Printf("users: department not found for user with id %d: %v", user.GetID(), err)
// 				}
// 			}

// 			if user.GetRoleID() != 0 {
// 				err = r.db.Model(&entities.Role{}).
// 					Where("id = ?", user.GetRoleID()).
// 					First(&role).Error
// 				if err != nil || role == nil {
// 					log.Printf("users: role not found for role_id %d: %v", user.GetRoleID(), err)
// 				}
// 			}

// 			if user.GetCreatedBy() != 0 {
// 				err = r.db.Table(AdminTableName).
// 					Where("id = ?", user.GetCreatedBy()).
// 					First(&creator).Error
// 				if err != nil || creator == nil {
// 					log.Printf("users: creator not found for admin_id %d: %v", user.GetCreatedBy(), err)
// 				}
// 			}

// 			if user.GetUpdatedBy() != 0 {
// 				err = r.db.Table(AdminTableName).
// 					Where("id = ?", user.GetUpdatedBy()).
// 					First(&updator).Error
// 				if err != nil || updator == nil {
// 					log.Printf("users: updator not found for admin_id %d: %v", user.GetUpdatedBy(), err)
// 				}
// 			}

// 			response := entities.KMSUserResponse{
// 				ID:        user.GetID(),
// 				BUserID:   user.GetBUserID(),
// 				FirstName: user.GetFirstName(),
// 				LastName:  user.GetLastName(),
// 				Department: &entities.DepartmentLite{
// 					ID: user.GetDepartmentID(),
// 				},
// 				Email:          user.GetEmail(),
// 				Mobile:         user.GetMobile(),
// 				LastLogin:      user.GetLastLogin(),
// 				LastPassChange: user.GetLastPassChange(),
// 				TelegramID:     user.GetTelegramID(),
// 				Role: &entities.RoleLite{
// 					ID: user.GetRoleID(),
// 				},
// 				ValidFrom:               user.GetValidFrom(),
// 				ValidTill:               user.GetValidTill(),
// 				UserStatus:              user.GetUserStatus(),
// 				CardID:                  user.GetCardID(),
// 				CardNo:                  user.GetCardNo(),
// 				CreatedBy:               user.GetCreatedBy(),
// 				UpdatedBy:               user.GetUpdatedBy(),
// 				CreatedAt:               user.GetCreatedAt(),
// 				UpdatedAt:               user.GetUpdatedAt(),
// 				LastActivityIndicatedAt: user.GetLastActivityIndicatedAt(),
// 				LastReminderSentAt:      user.GetLastReminderSentAt(),
// 				UserInactivatedAt:       user.GetUserInactivatedAt(),
// 			}

// 			if department != nil {
// 				response.Department.Name = department.Name
// 				response.Department.Description = department.Description
// 			}
// 			if role != nil {
// 				response.Role.Name = role.Name
// 			}
// 			if creator != nil {
// 				response.Creator = &entities.KMSAdminLite{
// 					ID:        creator.GetID(),
// 					FirstName: creator.GetFirstName(),
// 					LastName:  creator.GetLastName(),
// 					RoleID:    creator.GetRoleID(),
// 				}
// 			}
// 			if updator != nil {
// 				response.Updator = &entities.KMSAdminLite{
// 					ID:        updator.GetID(),
// 					FirstName: updator.GetFirstName(),
// 					LastName:  updator.GetLastName(),
// 					RoleID:    updator.GetRoleID(),
// 				}
// 			}

// 			responses = append(responses, response)
// 		}
// 		return responses, count, nil
// 	} else if userType == "KMSadmin" {
// 		var responses []entities.KMSAdminResponse
// 		for _, user := range users {
// 			var department *entities.Department
// 			var role *entities.Role
// 			var creator, updator *entities.KMSAdmin
// 			var err error

// 			if user.GetDepartmentID() != 0 {
// 				err = r.db.Model(&entities.Department{}).
// 					Where("id = ?", user.GetDepartmentID()).
// 					First(&department).Error
// 				if err != nil || department == nil {
// 					log.Printf("users: department not found for user with id %d: %v", user.GetID(), err)
// 				}
// 			}

// 			if user.GetRoleID() != 0 {
// 				err = r.db.Model(&entities.Role{}).
// 					Where("id = ?", user.GetRoleID()).
// 					First(&role).Error
// 				if err != nil || role == nil {
// 					log.Printf("users: role not found for role_id %d: %v", user.GetRoleID(), err)
// 				}
// 			}

// 			if user.GetCreatedBy() != 0 {
// 				err = r.db.Table(AdminTableName).
// 					Where("id = ?", user.GetCreatedBy()).
// 					First(&creator).Error
// 				if err != nil || creator == nil {
// 					log.Printf("users: creator not found for admin_id %d: %v", user.GetCreatedBy(), err)
// 				}
// 			}

// 			if user.GetUpdatedBy() != 0 {
// 				err = r.db.Table(AdminTableName).
// 					Where("id = ?", user.GetUpdatedBy()).
// 					First(&updator).Error
// 				if err != nil || updator == nil {
// 					log.Printf("users: updator not found for admin_id %d: %v", user.GetUpdatedBy(), err)
// 				}
// 			}

// 			response := entities.KMSAdminResponse{
// 				ID:        user.GetID(),
// 				FirstName: user.GetFirstName(),
// 				LastName:  user.GetLastName(),
// 				Department: &entities.DepartmentLite{
// 					ID: user.GetDepartmentID(),
// 				},
// 				Email:          user.GetEmail(),
// 				Mobile:         user.GetMobile(),
// 				Username:       user.GetUsername(),
// 				LastLogin:      user.GetLastLogin(),
// 				LastPassChange: user.GetLastPassChange(),
// 				TelegramID:     user.GetTelegramID(),
// 				Role: &entities.RoleLite{
// 					ID: user.GetRoleID(),
// 				},
// 				// CreatedBy:          user.GetCreatedBy(),
// 				// UpdatedBy:          user.GetUpdatedBy(),
// 				ValidFrom:          user.GetValidFrom(),
// 				ValidTill:          user.GetValidTill(),
// 				UserStatus:         user.GetUserStatus(),
// 				CardNo:             user.GetCardNo(),
// 				CreatedBy:          user.GetCreatedBy(),
// 				UpdatedBy:          user.GetUpdatedBy(),
// 				CreatedAt:          user.GetCreatedAt(),
// 				UpdatedAt:          user.GetUpdatedAt(),
// 				LastReminderSentAt: user.GetLastReminderSentAt(),
// 				UserInactivatedAt:  user.GetUserInactivatedAt(),
// 			}

// 			if user.GetCardID() != nil {
// 				response.CardID = user.GetCardID()
// 			}
// 			if department != nil {
// 				response.Department.Name = department.Name
// 				response.Department.Description = department.Description
// 			}
// 			if role != nil {
// 				response.Role.Name = role.Name
// 			}
// 			if creator != nil {
// 				response.Creator = &entities.KMSAdminLite{
// 					ID:        creator.GetID(),
// 					FirstName: creator.GetFirstName(),
// 					LastName:  creator.GetLastName(),
// 					RoleID:    creator.GetRoleID(),
// 				}
// 			}
// 			if updator != nil {
// 				response.Updator = &entities.KMSAdminLite{
// 					ID:        updator.GetID(),
// 					FirstName: updator.GetFirstName(),
// 					LastName:  updator.GetLastName(),
// 					RoleID:    updator.GetRoleID(),
// 				}
// 			}

// 			responses = append(responses, response)
// 		}
// 		return responses, count, nil
// 	}

// 	return nil, 0, nil
// }

// // Get users or admins lite
// func (r *mysqlRepo) GetUsersLite(userType string, ctx context.Context) (interface{}, int, error) {
// 	var count int64
// 	switch userType {
// 	case "KMSuser":
// 		var users []entities.KMSUserLite
// 		if err := r.db.Table("users").
// 			Count(&count).
// 			Find(&users).Error; err != nil {
// 			return nil, 0, err
// 		}
// 		return &users, int(count), nil
// 	case "KMSadmin":
// 		var admins []entities.KMSAdminLite
// 		if err := r.db.Table("admins").
// 			Count(&count).
// 			Find(&admins).Error; err != nil {
// 			return nil, 0, err
// 		}
// 		return &admins, int(count), nil
// 	default:
// 		return nil, 0, errors.New("expect 'KMSuser' or 'KMSadmin' only")
// 	}
// }

// func (r *mysqlRepo) GetUsersFromTable(page, size int, sortBy, sortOrder string, filters map[string]string, tableName string, users interface{}, ctx context.Context) (int, error) {
// 	// Check if the database connection is nil
// 	if r.db == nil {
// 		return 0, fmt.Errorf("field: nil, message: Database connection is nil")
// 	}

// 	var count int64

// 	// Start building the query
// 	query := r.db.WithContext(ctx).Table(tableName)

// 	// Apply filters if any
// 	query = ApplyFilters(query, filters)

// 	// Count query
// 	if err := query.Count(&count).Error; err != nil {
// 		return 0, err
// 	}

// 	// Apply sorting if any
// 	if sortBy != "" {
// 		if sortOrder != "asc" && sortOrder != "desc" {
// 			return 0, errors.New("field: sort, message: Invalid sort order - must be 'asc' or 'desc'")
// 		}
// 		query = query.Order(fmt.Sprintf("%s %s", sortBy, sortOrder))
// 	}

// 	// Apply pagination if any
// 	if size > 0 {
// 		query = query.Limit(size)
// 	}
// 	offset := (page - 1) * size
// 	if offset > 0 {
// 		query = query.Offset(offset)
// 	}

// 	// Execute the query and populate the users interface
// 	if err := query.Find(users).Error; err != nil {
// 		return 0, fmt.Errorf("field: nil, message: Failed to fetch data from table %s [%w]", tableName, err)
// 	}

// 	return int(count), nil
// }

// // func (r *mysqlUserRepository) GetUsersFromTable(filters map[string]string, tableName string, users interface{}, ctx context.Context) error {
// // 	tx := r.db.WithContext(ctx)
// // 	if r.db == nil {
// // 		return fmt.Errorf("database connection is nil")
// // 	}
// // 	return tx.Table(tableName).WithContext(ctx).Find(users).Error
// // }

// // func (r *mysqlUserRepository) StoreToken(accessToken string, ctx context.Context) error {
// //
// //	accessTokenStore := &entities.AccessToken{
// //			Token: accessToken,
// //		}
// //		return r.db.WithContext(ctx).Create(accessTokenStore).Error
// //	}

// func (r *mysqlRepo) ActivateUser(userID uint, ctx context.Context) error {
// 	const StatusActivated int = 1
// 	now := time.Now()

// 	if err := r.db.WithContext(ctx).
// 		Table(UserTableName).
// 		Where("id = ?", userID).
// 		Updates(map[string]any{
// 			"user_status":                StatusActivated,
// 			"last_activity_indicated_at": now,
// 		}).Error; err != nil {
// 		log.Printf("[USER] Failed to activate user %d: %v", userID, err)
// 		return err
// 	}

// 	go r.AddChangeLogs([]entities.ChangeLog{{
// 		TableName:  UserTableName,
// 		Action:     entities.ActionUpdate,
// 		ChangeTime: now,
// 		Data: map[string]any{
// 			"id":                         userID,
// 			"status":                     StatusActivated,
// 			"last_activity_indicated_at": now,
// 		},
// 	}})

// 	return nil
// }

// func (r *mysqlRepo) DeleteKMSUser(ctx context.Context, userID uint) error {
// 	const RoleUser int = 4
// 	var cls []entities.ChangeLog
// 	now := time.Now()

// 	// Step 1: Fetch user with user_id
// 	var kms_user entities.KMSUser
// 	if err := r.db.Table(UserTableName).
// 		Where("id = ?", userID).
// 		First(&kms_user).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return fmt.Errorf("KMSUser with id %d not found", userID)
// 		}
// 		return fmt.Errorf("failed to fetch KMSUser: %w", err)
// 	}

// 	// Step 2: Start a database transaction
// 	tx := r.db.Begin()
// 	if tx.Error != nil {
// 		return fmt.Errorf("failed to start transaction for delete user: %w", tx.Error)
// 	}

// 	// Step 3: Delete kms_user.user_usergroups
// 	var deleted []uint
// 	if err := tx.Model(&entities.UserUserGroup{}).
// 		Where("user_id = ? AND role_id = ?", userID, RoleUser).
// 		Pluck("usergroup_id", &deleted).Error; err != nil {
// 		tx.Rollback()
// 		return fmt.Errorf("failed to fetch usergroup_id: %w", err)
// 	}
// 	result := tx.Model(&entities.UserUserGroup{}).
// 		Where("user_id = ? AND role_id = ?", userID, RoleUser).
// 		Delete(&entities.UserUserGroup{})
// 	if result.Error != nil {
// 		tx.Rollback()
// 		return fmt.Errorf("failed to delete user_usergroups: %w", result.Error)
// 	}

// 	for _, d := range deleted {
// 		cls = append(cls, entities.ChangeLog{
// 			TableName:  entities.UserUserGroup{}.TableName(),
// 			Action:     entities.ActionDelete,
// 			ChangeTime: now,
// 			Data: map[string]uint{
// 				"user_id":      userID,
// 				"usergroup_id": d,
// 			},
// 		})
// 	}

// 	// Step 4: Delete kms_user.users
// 	result = tx.Table(UserTableName).
// 		Where("id = ?", userID).
// 		Delete(&entities.KMSUser{})
// 	if result.Error != nil {
// 		tx.Rollback()
// 		return fmt.Errorf("failed to delete user: %w", result.Error)
// 	}
// 	cls = append(cls, entities.ChangeLog{
// 		TableName:  UserTableName,
// 		Action:     entities.ActionDelete,
// 		ChangeTime: now,
// 		Data:       map[string]uint{"id": userID},
// 	})

// 	// Step 5: Commit transaction if all steps succeed
// 	if err := tx.Commit().Error; err != nil {
// 		return fmt.Errorf("failed to commit transaction: %w", err)
// 	}

// 	// Step 6: Log delete events
// 	delete_log := entities.DeleteLog{
// 		EntityType:  "user",
// 		AttributeID: userID,
// 		Name:        strings.TrimSpace(fmt.Sprintf("%s %s", kms_user.GetFirstName(), kms_user.GetLastName())),
// 		DeletedAt:   time.Now(),
// 	}
// 	if kms_user.GetBUserID() != nil {
// 		delete_log.BUserID = *kms_user.GetBUserID()
// 	}
// 	err := r.LogDelete(delete_log)
// 	if err != nil {
// 		log.Printf("[USERS] Failed to log delete events for user_id %d with b_user_id %d: %v",
// 			userID, kms_user.GetBUserID(), err)
// 	}

// 	// Step 7: Delete dependencies in kms_server
// 	err = r.DeleteKMSDependencies(delete_log)
// 	if err != nil {
// 		log.Printf("[USERS] Failed to delete dependencies for %s with id %d: %v", delete_log.EntityType, userID, err)
// 	}

// 	// Step 8: Add change-log
// 	go r.AddChangeLogs(cls)

// 	log.Printf("[USERS] Successfully deleted users: %v", userID)
// 	return nil
// }

// func (r *mysqlRepo) DeleteKMSAdmin(ctx context.Context, userID uint) error {
// 	// Step 1: Delete `admin`
// 	result := r.db.Table(AdminTableName).
// 		Where("id = ?", userID).
// 		Delete(&entities.KMSAdmin{})

// 	if result.Error != nil {
// 		return fmt.Errorf("failed to delete admin: %w", result.Error)
// 	}

// 	// Step 3: Log delete events
// 	delete_log := entities.DeleteLog{
// 		EntityType:  "admin",
// 		AttributeID: userID,
// 		DeletedAt:   time.Now(),
// 	}
// 	err := r.LogDelete(delete_log)
// 	if err != nil {
// 		log.Printf("users: failed to log delete events for admin_id %d: %v", userID, err)
// 	}

// 	// Step 4: Delete dependencies in kms_server
// 	err = r.DeleteKMSDependencies(delete_log)
// 	if err != nil {
// 		log.Printf("users: failed to delete dependencies for %s with id %d: %v", delete_log.EntityType, userID, err)
// 	}

// 	return nil
// }

// func (r *mysqlRepo) CheckFieldDuplicates(ctx context.Context, user_type string, field string, user_id uint, value interface{}) (bool, error) {
// 	// Step 1: Validate parameters
// 	if user_type == "" || field == "" {
// 		return false, errors.New("table or field cannot be empty")
// 	}

// 	// Step 2: Find matching table by user_type
// 	var table string
// 	switch user_type {
// 	case "KMSuser":
// 		table = UserTableName
// 	case "KMSadmin":
// 		table = AdminTableName
// 	}

// 	// Step 3: Query database to count occurences
// 	var count int64
// 	if err := r.db.Table(table).
// 		Where(fmt.Sprintf("%s = ? AND id != ?", field), value, user_id).
// 		Count(&count).Error; err != nil {
// 		return false, fmt.Errorf("error checking duplicates in table %s, field %s: %w", table, field, err)
// 	}

// 	// Step 4: Return true if duplicates exists, false otherwise
// 	return count > 0, nil
// }

// func (r *mysqlRepo) LogDelete(delete_log entities.DeleteLog) error {
// 	if err := r.db.Create(&delete_log).Error; err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (r *mysqlRepo) GetDeleteLogs(ctx context.Context, page, size int, sortBy, sortOrder string, filters map[string]string) (*[]entities.DeleteLog, int, error) {
// 	var logs []entities.DeleteLog
// 	var count int64

// 	if sortOrder != "asc" && sortOrder != "desc" {
// 		return nil, 0, errors.New("invalid sort order, must be 'asc' or 'desc'")
// 	}

// 	query := r.db.Model(&entities.DeleteLog{})
// 	if err := query.Count(&count).Error; err != nil {
// 		return nil, 0, err
// 	}
// 	for filterBy, filterValue := range filters {
// 		query = query.Where(fmt.Sprintf("%s = ?", filterBy), filterValue)
// 	}
// 	if sortBy != "" {
// 		query = query.Order(fmt.Sprintf("%s %s", sortBy, sortOrder))
// 	}
// 	if size > 0 {
// 		offset := (page - 1) * size
// 		query = query.Limit(size).Offset(offset)
// 	}

// 	if err := query.Find(&logs).Error; err != nil {
// 		return nil, 0, err
// 	}

// 	return &logs, int(count), nil
// }

// func (r *mysqlRepo) DeleteKMSDependencies(delete_log entities.DeleteLog) error {
// 	var payload map[string]interface{}
// 	var request_url string

// 	// Step 1: Construct payload and request_url based on dependency
// 	dependency := delete_log.EntityType
// 	switch dependency {
// 	case "admin":
// 		payload = map[string]interface{}{
// 			"userType": "KMSadmin", // `KMSadmin`
// 			"body": map[string]interface{}{
// 				"id": delete_log.AttributeID, // `admin_id`
// 			},
// 		}
// 		request_url = fmt.Sprintf("%s/kms/api/v1/dependencies", config.LoadConfig().APIURL_KMS)
// 	case "user":
// 		payload = map[string]interface{}{
// 			"userType": "KMSuser", // `KMSuser`
// 			"body": map[string]interface{}{
// 				"id":        delete_log.AttributeID, // `user_id`
// 				"b_user_id": delete_log.BUserID,     // `b_user_id`
// 				"name":      delete_log.Name,        // `name`
// 			},
// 		}
// 		request_url = fmt.Sprintf("%s/kms/api/v1/dependencies", config.LoadConfig().APIURL_KMS)
// 	case "usergroup":
// 		payload = map[string]interface{}{
// 			"body": []map[string]interface{}{
// 				{
// 					"user_group": map[string]interface{}{
// 						"id": delete_log.AttributeID, // `usergroup_id`
// 					},
// 				},
// 			},
// 		}
// 		request_url = fmt.Sprintf("%s/kms/api/v1/access/usergroup-keytaggroup", config.LoadConfig().APIURL_KMS)
// 	default:
// 		return fmt.Errorf("invalid dependency: %s, expecting `KMSadmin`/`KMSuser`/`KMSusergroup", dependency)
// 	}

// 	// Step 2: Convert payload to json
// 	json_payload, err := json.Marshal(payload)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal request: %w", err)
// 	}

// 	// Step 3: Send delete request
// 	request, err := http.NewRequest("DELETE", request_url, bytes.NewReader(json_payload))
// 	if err != nil {
// 		return fmt.Errorf("failed to create API request: %w", err)
// 	}

// 	request.Header.Set("x-api-key", config.LoadConfig().Internal_API_Key1)
// 	request.Header.Set("Content-Type", "application/json")

// 	client := &http.Client{Timeout: 30 * time.Second}
// 	response, err := client.Do(request)
// 	if err != nil {
// 		return fmt.Errorf("failed to send API request: %w", err)
// 	}
// 	defer response.Body.Close()

// 	// Step 4: Handle response status
// 	if response.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(response.Body)
// 		return fmt.Errorf("API request failed: status %d, response: %s", response.StatusCode, string(body))
// 	}

// 	return nil
// }

// func (r *mysqlRepo) GetEmails(user_ids []uint, user_type string, ctx context.Context) ([]map[string]string, error) {
// 	var users []struct {
// 		FirstName string `gorm:"column:first_name" json:"first_name"`
// 		LastName  string `gorm:"column:last_name" json:"last_name"`
// 		Email     string `gorm:"column:email" json:"email"`
// 	}
// 	var emails []map[string]string
// 	var table_name string

// 	switch user_type {
// 	case "KMSadmin":
// 		table_name = AdminTableName
// 	case "KMSuser":
// 		table_name = UserTableName
// 	default:
// 		return nil, fmt.Errorf("invalid user_type, expecting: `KMSuser` or `KMSadmin`")
// 	}

// 	result := r.db.Table(table_name).
// 		Select("first_name, last_name, email").
// 		Where("id IN (?)", user_ids).
// 		Scan(&users)
// 	if result.Error != nil {
// 		return nil, fmt.Errorf("failed to fetch users for user_ids %v: %v", user_ids, result.Error)
// 	}

// 	for _, user := range users {
// 		user_name := strings.TrimSpace(fmt.Sprintf("%s %s", user.FirstName, user.LastName))
// 		emails = append(emails, map[string]string{
// 			user_name: user.Email,
// 		})
// 	}

// 	return emails, nil
// }

// func (r *mysqlRepo) GetUserByMobile(ctx context.Context, mobile int) (*entities.KMSUserResponse, error) {
// 	var user entities.KMSUser
// 	result := r.db.Table(UserTableName).Where("mobile = ?", uint(mobile)).First(&user)
// 	if result.Error != nil {
// 		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 			return nil, fmt.Errorf("user not found for mobile: %d", mobile)
// 		}
// 		return nil, fmt.Errorf("database error: %v", result.Error)
// 	}

// 	var department *entities.Department
// 	if user.GetDepartmentID() != 0 {
// 		err := r.db.Model(&entities.Department{}).
// 			Where("id = ?", user.GetDepartmentID()).
// 			First(&department).Error
// 		if err != nil || department == nil {
// 			log.Printf("users: department not found for user with id %d: %v", user.GetID(), err)
// 		}
// 	}

// 	var role *entities.Role
// 	if user.GetRoleID() != 0 {
// 		err := r.db.Model(&entities.Role{}).
// 			Where("id = ?", user.GetRoleID()).
// 			First(&role).Error
// 		if err != nil || role == nil {
// 			log.Printf("users: role not found for role_id %d: %v", user.GetRoleID(), err)
// 		}
// 	}

// 	response := entities.KMSUserResponse{
// 		ID:        user.GetID(),
// 		BUserID:   user.GetBUserID(),
// 		FirstName: user.GetFirstName(),
// 		LastName:  user.GetLastName(),
// 		Department: &entities.DepartmentLite{
// 			ID: user.GetDepartmentID(),
// 		},
// 		Email:          user.GetEmail(),
// 		Mobile:         user.GetMobile(),
// 		LastLogin:      user.GetLastLogin(),
// 		LastPassChange: user.GetLastPassChange(),
// 		TelegramID:     user.GetTelegramID(),
// 		Role: &entities.RoleLite{
// 			ID: user.GetRoleID(),
// 		},
// 		// CreatedBy:               user.GetCreatedBy(),
// 		// UpdatedBy:               user.GetUpdatedBy(),
// 		ValidFrom:               user.GetValidFrom(),
// 		ValidTill:               user.GetValidTill(),
// 		UserStatus:              user.GetUserStatus(),
// 		CardNo:                  user.GetCardNo(),
// 		CreatedAt:               user.GetCreatedAt(),
// 		UpdatedAt:               user.GetUpdatedAt(),
// 		LastActivityIndicatedAt: user.GetLastActivityIndicatedAt(),
// 		LastReminderSentAt:      user.GetLastReminderSentAt(),
// 		UserInactivatedAt:       user.GetUserInactivatedAt(),
// 	}

// 	if user.GetCardID() != nil {
// 		response.CardID = user.GetCardID()
// 	}
// 	if department != nil {
// 		response.Department.Name = department.Name
// 	}
// 	if role != nil {
// 		response.Role.Name = role.Name
// 	}

// 	return &response, nil
// }

// // Internal function: apply filters based on field type
// func ApplyFilters(query *gorm.DB, filters map[string]string) *gorm.DB {
// 	isNumber := regexp.MustCompile(`^-?\d+(\.\d+)?$`)

// 	for filterBy, filterValue := range filters {
// 		switch filterBy {
// 		case "mobile":
// 			query = query.Where(fmt.Sprintf("%s LIKE ?", filterBy), fmt.Sprintf("%%%s%%", filterValue))
// 			continue
// 		case "b_user_id":
// 			query = query.Where(fmt.Sprintf("%s = ?", filterBy), filterValue)
// 			continue
// 		case "card_id_like":
// 			query = query.Where("card_id LIKE ?", fmt.Sprintf("%%%s%%", filterValue))
// 			continue
// 		default:
// 			if isNumber.MatchString(filterValue) {
// 				query = query.Where(fmt.Sprintf("%s = ?", filterBy), filterValue)
// 			} else {
// 				query = query.Where(fmt.Sprintf("%s LIKE ?", filterBy), fmt.Sprintf("%%%s%%", filterValue))
// 			}
// 		}
// 	}

// 	return query
// }

// // Retrieve user_id and role_id from jwt token
// func (r *mysqlRepo) GetDetailsFromToken(tokenString string) (uint, uint, error) {
// 	// Step 1: Parse the token
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		// Ensure signing method is valid
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, errors.New("unexpected signing method")
// 		}
// 		return []byte(config.LoadConfig().AccessTokenSecret), nil
// 	})

// 	if err != nil {
// 		return 0, 0, errors.New("failed to parse token: " + err.Error())
// 	}

// 	// Step 2: Extract claims from the token
// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok || !token.Valid {
// 		return 0, 0, errors.New("invalid token claims")
// 	}

// 	// Step 3: Extract and convert `user_id`
// 	userID, ok := claims["user_id"].(float64) // JWT claims default to float64
// 	if !ok {
// 		return 0, 0, errors.New("user_id claim is not a valid number")
// 	}

// 	// Step 4: Extract and convert `role_id`
// 	roleID, ok := claims["role_id"].(float64) // JWT claims default to float64
// 	if !ok {
// 		return 0, 0, errors.New("role_id claim is not a valid number")
// 	}

// 	return uint(userID), uint(roleID), nil
// }

// func (r *mysqlRepo) GetUserByMobileCard(identifier uint) (map[string]interface{}, error) {
// 	var user entities.KMSUser

// 	query := r.db.Table(UserTableName)
// 	query = query.Where("mobile = ? or card_id = ?", identifier, identifier)

// 	result := query.First(&user)
// 	if result.Error != nil {
// 		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
// 			return nil, fmt.Errorf("failed to find user by mobile or card_id")
// 		}
// 		return nil, fmt.Errorf("database error: %v", result.Error)
// 	}

// 	var department *entities.Department
// 	if user.GetDepartmentID() != 0 {
// 		err := r.db.Model(&entities.Department{}).
// 			Where("id = ?", user.GetDepartmentID()).
// 			First(&department).Error
// 		if err != nil || department == nil {
// 			log.Printf("users: department not found for user with id %d: %v", user.GetID(), err)
// 		}
// 	}

// 	response := map[string]interface{}{
// 		"id":         user.GetID(),
// 		"first_name": user.GetFirstName(),
// 		"last_name":  user.GetLastName(),
// 		"department": nil,
// 		"email":      user.GetEmail(),
// 		"mobile":     user.GetMobile(),
// 		"valid_till": user.GetValidTill(),
// 		"card_id":    user.GetCardID(),
// 		"card_no":    user.GetCardNo(),
// 		"b_user_id":  user.GetBUserID(),
// 	}

// 	if department != nil {
// 		response["department"] = &entities.DepartmentLite{
// 			ID:   user.GetDepartmentID(),
// 			Name: department.Name,
// 		}
// 	}

// 	return response, nil
// }

// func (r *mysqlRepo) GetUsersByBUserIDs(bUserIDs []uint) (*[]entities.KMSUserLite, error) {
// 	var users []entities.KMSUserLite
// 	if err := r.db.Table(UserTableName).
// 		Where("b_user_id IN ?", bUserIDs).
// 		Find(&users).Error; err != nil {
// 		return nil, err
// 	}
// 	return &users, nil
// }

// func (r *mysqlRepo) GetTelegramIDs() ([]uint, error) {
// 	var telegramIDs []uint
// 	if err := r.db.Table(AdminTableName).
// 		Where("telegram_id IS NOT NULL AND telegram_id > 0").
// 		Pluck("telegram_id", &telegramIDs).Error; err != nil {
// 		return nil, err
// 	}
// 	return telegramIDs, nil
// }

// func (r *mysqlRepo) GetAllUsersV2(params entities.QueryParam) (any, uint, error) {
// 	var users []entities.KMSUser
// 	var count int64

// 	query := r.db.Model(&entities.KMSUser{})
// 	fields := []string{"id", "src_db", "b_user_id", "first_name", "last_name",
// 		"department_id", "email", "mobile", "user_status",
// 		"last_login", "last_pass_change", "role_id", "card_no",
// 		"card_id", "valid_from", "valid_till", "telegram_id",
// 		"created_by", "created_at", "updated_by", "updated_at"}

// 	query, err := applyFilters(query, params, fields)
// 	if err != nil {
// 		return nil, 0, err
// 	}
// 	if err := query.Count(&count).Error; err != nil {
// 		return nil, 0, err
// 	}

// 	query = applySort(query, params)
// 	query = applyPagination(query, params)

// 	if !params.Lite {
// 		query = query.Preload("Department").Preload("Role")
// 	}
// 	if err := query.Find(&users).Error; err != nil {
// 		return nil, 0, err
// 	}

// 	if params.Lite {
// 		responses := make([]entities.KMSUserLite, len(users))
// 		for i, u := range users {
// 			responses[i] = entities.KMSUserLite{
// 				ID:        u.ID,
// 				BUserID:   u.BUserID,
// 				FirstName: u.FirstName,
// 				LastName:  u.LastName,
// 				RoleID:    u.RoleID,
// 			}
// 		}
// 		return responses, uint(count), nil
// 	}

// 	adminMap, err := r.GetAdminLiteMap()
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	responses := make([]entities.KMSUserResponse, len(users))
// 	for i, u := range users {
// 		resp := mapUserToResponse(u)
// 		if creator, ok := adminMap[u.CreatedBy]; ok {
// 			resp.Creator = &creator
// 		}
// 		if updator, ok := adminMap[u.UpdatedBy]; ok {
// 			resp.Updator = &updator
// 		}
// 		responses[i] = resp
// 	}
// 	return responses, uint(count), nil
// }

// func (r *mysqlRepo) GetAllAdminsV2(params entities.QueryParam) (any, uint, error) {
// 	var admins []entities.KMSAdmin
// 	var count int64

// 	query := r.db.Model(&entities.KMSAdmin{})
// 	fields := []string{
// 		"id", "first_name", "last_name", "department_id", "email",
// 		"mobile", "user_status", "last_login", "last_pass_change",
// 		"role_id", "card_no", "card_id", "valid_from", "valid_till",
// 		"telegram_id", "username", "created_by", "created_at", "updated_by", "updated_at",
// 	}

// 	query, err := applyFilters(query, params, fields)
// 	if err != nil {
// 		return nil, 0, err
// 	}
// 	if err := query.Count(&count).Error; err != nil {
// 		return nil, 0, err
// 	}

// 	query = applySort(query, params)
// 	query = applyPagination(query, params)

// 	if !params.Lite {
// 		query = query.Preload("Department").Preload("Role")
// 	}
// 	if err := query.Find(&admins).Error; err != nil {
// 		return nil, 0, err
// 	}

// 	if params.Lite {
// 		responses := make([]entities.KMSAdminLite, len(admins))
// 		for i, a := range admins {
// 			responses[i] = entities.KMSAdminLite{
// 				ID:        a.ID,
// 				FirstName: a.FirstName,
// 				LastName:  a.LastName,
// 				RoleID:    a.RoleID,
// 			}
// 		}
// 		return responses, uint(count), nil
// 	}

// 	adminMap, err := r.GetAdminLiteMap()
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	responses := make([]entities.KMSAdminResponse, len(admins))
// 	for i, u := range admins {
// 		resp := mapAdminToResponse(u)
// 		if creator, ok := adminMap[u.CreatedBy]; ok {
// 			resp.Creator = &creator
// 		}
// 		if updator, ok := adminMap[u.UpdatedBy]; ok {
// 			resp.Updator = &updator
// 		}
// 		responses[i] = resp
// 	}
// 	return responses, uint(count), nil
// }

// func (r *mysqlRepo) GetAdminLiteMap() (map[uint]entities.KMSAdminLite, error) {
// 	var admins []entities.KMSAdmin
// 	if err := r.db.Find(&admins).Error; err != nil {
// 		return nil, err
// 	}

// 	adminMap := make(map[uint]entities.KMSAdminLite, len(admins))
// 	for _, a := range admins {
// 		adminMap[a.ID] = entities.KMSAdminLite{
// 			ID:        a.ID,
// 			FirstName: a.FirstName,
// 			LastName:  a.LastName,
// 			RoleID:    a.RoleID,
// 		}
// 	}
// 	return adminMap, nil
// }

// func mapUserToResponse(u entities.KMSUser) entities.KMSUserResponse {
// 	resp := entities.KMSUserResponse{
// 		ID:                      u.ID,
// 		BUserID:                 u.BUserID,
// 		FirstName:               u.FirstName,
// 		LastName:                u.LastName,
// 		Email:                   u.Email,
// 		Mobile:                  u.Mobile,
// 		LastLogin:               u.LastLogin,
// 		LastPassChange:          u.LastPassChange,
// 		TelegramID:              u.TelegramID,
// 		ValidFrom:               u.ValidFrom,
// 		ValidTill:               u.ValidTill,
// 		UserStatus:              u.UserStatus,
// 		CardNo:                  u.CardNo,
// 		CardID:                  u.CardID,
// 		CreatedAt:               u.CreatedAt,
// 		UpdatedAt:               u.UpdatedAt,
// 		LastActivityIndicatedAt: u.LastActivityIndicatedAt,
// 		LastReminderSentAt:      u.LastReminderSentAt,
// 		UserInactivatedAt:       u.UserInactivatedAt,
// 	}
// 	if u.Department != nil {
// 		resp.Department = &entities.DepartmentLite{
// 			ID:          u.DepartmentID,
// 			Name:        u.Department.Name,
// 			Description: u.Department.Description,
// 		}
// 	}
// 	if u.Role != nil {
// 		resp.Role = &entities.RoleLite{
// 			ID:   u.RoleID,
// 			Name: u.Role.Name,
// 		}
// 	}
// 	return resp
// }

// func mapAdminToResponse(a entities.KMSAdmin) entities.KMSAdminResponse {
// 	resp := entities.KMSAdminResponse{
// 		ID:                 a.ID,
// 		FirstName:          a.FirstName,
// 		LastName:           a.LastName,
// 		Email:              a.Email,
// 		Mobile:             a.Mobile,
// 		LastLogin:          a.LastLogin,
// 		LastPassChange:     a.LastPassChange,
// 		TelegramID:         a.TelegramID,
// 		ValidFrom:          a.ValidFrom,
// 		ValidTill:          a.ValidTill,
// 		UserStatus:         a.UserStatus,
// 		CardNo:             a.CardNo,
// 		CardID:             a.CardID,
// 		CreatedAt:          a.CreatedAt,
// 		UpdatedAt:          a.UpdatedAt,
// 		LastReminderSentAt: a.LastReminderSentAt,
// 		UserInactivatedAt:  a.UserInactivatedAt,
// 	}
// 	if a.Department != nil {
// 		resp.Department = &entities.DepartmentLite{
// 			ID:          a.DepartmentID,
// 			Name:        a.Department.Name,
// 			Description: a.Department.Description,
// 		}
// 	}
// 	if a.Role != nil {
// 		resp.Role = &entities.RoleLite{
// 			ID:   a.RoleID,
// 			Name: a.Role.Name,
// 		}
// 	}
// 	return resp
// }
