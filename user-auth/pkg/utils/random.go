package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
	"user-auth/internal/entities"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/"
const alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomLetters(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randomAlphanumeric(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = alphanum[rand.Intn(len(alphanum))]
	}
	return string(b)
}

func randomPassword(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = passwordCharset[rand.Intn(len(passwordCharset))]
	}
	return string(b)
}

func randomEmail(first, last string) string {
	domains := []string{"example.com", "testmail.com", "demo.org"}
	num := rand.Intn(9999)
	return strings.ToLower(first) + "." + strings.ToLower(last) + fmt.Sprintf("%d@%s", num, domains[rand.Intn(len(domains))])
}
func randomTimeBetween(start, end time.Time) time.Time {
	diff := end.Sub(start)
	return start.Add(time.Duration(rand.Int63n(int64(diff))))
}

func GenerateRandomUser() entities.UserMember {
	now := time.Now()
	first := randomLetters(6)
	last := randomLetters(8)
	username := randomAlphanumeric(10)
	password := randomPassword(16)

	mobile := 9000000000 + rand.Intn(99999999)

	validFrom := now.AddDate(0, -rand.Intn(12), 0)
	validTill := validFrom.AddDate(1, 0, 0)

	lastLogin := randomTimeBetween(now.AddDate(-1, 0, 0), now)
	lastPassChange := randomTimeBetween(now.AddDate(-1, 0, 0), now)

	return entities.UserMember{
		User: entities.User{
			FirstName:      first,
			LastName:       last,
			Email:          randomEmail(first, last),
			Mobile:         uint64(mobile),
			LastLogin:      &lastLogin,
			LastPassChange: &lastPassChange,
			ValidFrom:      entities.NullDateOnly{Date: entities.DateOnly(validFrom), Valid: true},
			ValidTill:      entities.NullDateOnly{Date: entities.DateOnly(validTill), Valid: true},
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		LastActivityIndicatedAt: now,
		Password:                password,
		Status:                  1,
		Username:                username,
		LastReminderSentAt:      &now,
		UserInactivatedAt:       nil,
	}
}
