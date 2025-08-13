package auth_util

import "user-auth/internal/entities"

func SanitizeUser(user entities.UserInterface) entities.UserInterface {
	switch u := user.(type) {
	case *entities.UserMember:
		sanitizedUser := &entities.UserMember{
			User: u.User,

			Status:             u.Status,
			Username:           u.Username,
			LastReminderSentAt: u.LastReminderSentAt,
			UserInactivatedAt:  u.UserInactivatedAt,
		}

		return sanitizedUser
		// // Only add DateOnly fields if they are not zero values
		// if u.AssetValidFrom != (entities.DateOnly{}) {
		// 	sanitizedUser.AssetValidFrom = u.AssetValidFrom
		// } else {
		// 	sanitizedUser.AssetValidFrom = nil // Or just omit it if you don't want to set it to null
		// }
		// return sanitizedUser

		// return &entities.KMSAdmin{
		// 	User:           u.User,
		// 	AssetValidFrom: u.AssetValidFrom,
		// 	AssetValidTill: u.AssetValidTill,
		// 	CardID:         u.CardID,
		// 	CardNo:         u.CardNo,
		// 	ValidFrom:      u.ValidFrom,
		// 	ValidTill:      u.ValidTill,
		// 	RoleID:         u.RoleID,
		// 	CreatedBy:      u.CreatedBy,
		// 	UpdatedBy:      u.UpdatedBy,
		// 	DepartmentID:   u.DepartmentID,
		// 	UserStatus:     u.UserStatus,
		// 	Username:       u.Username,
		// 	TelegramID:     u.TelegramID,
		// }

	// case *entities.LorawanAdmin:
	// 	return &entities.LorawanAdmin{
	// 		User:       u.User,
	// 		TelegramID: u.TelegramID,
	// 		ValidFrom:  u.ValidFrom,
	// 		ValidTill:  u.ValidTill,
	// 	}
	default:
		return user
	}
}
