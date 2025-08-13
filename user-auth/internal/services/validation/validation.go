package validation

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"user-auth/internal/entities"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

func ValidateBaseUser(user *entities.User) error {
	validate := validator.New()
	return validate.Struct(user)
}

func ValidateUserMember(user *entities.UserMember) error {
	if err := ValidateBaseUser(&user.User); err != nil {
		return err
	}

	// validate admin fields
	return nil
}

func ValidateUser(user entities.UserInterface) error {
	switch u := user.(type) {
	case *entities.UserMember:
		return ValidateUserMember(u)
	// case *entities.LorawanAdmin:
	// 	return ValidateLorawanAdminUser(u)
	default:
		return errors.New("unknown project user type")
	}
}

func ComparePasswords(hashedPassword, plainPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	return err == nil
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func ValidatePasswordStrength(newPassword string) error {
	// check space
	if strings.Contains(newPassword, " ") {
		return errors.New("password cannot contain spaces")
	}
	// Minimum length of 10 characters
	if len(newPassword) < 10 {
		return errors.New("password must be at least 10 characters long")
	}
	// Max 100
	if len(newPassword) > 100 {
		return errors.New("password must be no more than 100 characters long")
	}

	// Unspecified characters not allowed
	for _, char := range newPassword {
		if char > unicode.MaxASCII {
			return errors.New("password can only contain alphabets/numbers/special characters")
		}
	}

	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(newPassword)
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(newPassword)
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}

	// Check for at least two digits
	digitCount := regexp.MustCompile(`[0-9]`).FindAllString(newPassword, -1)
	if len(digitCount) < 2 {
		return errors.New("password must contain at least two digits")
	}

	// Check for simple patterns like "password" or "password123"
	commonPasswords := []string{
		"password", "password123", "123456", "qwerty", "admin", "letmein", "welcome",
	}

	for _, common := range commonPasswords {
		if strings.ToLower(newPassword) == common {
			return errors.New("password is too common")
		}
	}

	// Check for simple patterns with alternating case like "Password123" or "PASSword123"
	if matched, _ := regexp.MatchString(`[A-Za-z0-9]+`, newPassword); matched {
		for _, c := range commonPasswords {
			// Check case-insensitive match for variants of common passwords
			if strings.Contains(strings.ToLower(newPassword), strings.ToLower(c)) {
				return errors.New("password is too similar to a common pattern")
			}
		}
	}
	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(newPassword)
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	return nil
}
