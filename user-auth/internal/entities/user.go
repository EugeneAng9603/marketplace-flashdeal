package entities

import (
	"time"
)

type UserInterface interface {
	GetID() uint
	GetFirstName() string
	GetLastName() string
	GetMobile() uint64
	GetEmail() string
	GetUserStatus() uint8
	GetLastLogin() *time.Time
	GetLastPassChange() *time.Time
	GetCreatedAt() time.Time
	GetUpdatedAt() time.Time
	SetLastPassChange(*time.Time)
	SetLastLogin(*time.Time)
	SetCreatedAt(time.Time)
	SetUpdatedAt(time.Time)
	SetFirstName(string)
	SetLastName(string)
	SetMobile(uint64)
	SetEmail(string)
	//SetPassword(string)
	SetID(id uint)
	GetValidFrom() NullDateOnly
	GetValidTill() NullDateOnly
	SetValidFrom(time.Time)
	EnsureValidFromIsSet()
	GetLastActivityIndicatedAt() time.Time
	GetLastReminderSentAt() *time.Time
	GetUserInactivatedAt() *time.Time
	GetUsername() string
}

type User struct {
	ID             uint         `gorm:"primaryKey" json:"id"`
	FirstName      string       `json:"first_name"`
	LastName       string       `json:"last_name"`
	Email          string       `json:"email"`
	Mobile         uint64       `json:"mobile"`
	LastLogin      *time.Time   `json:"last_login"`
	LastPassChange *time.Time   `json:"last_pass_change"`
	ValidFrom      NullDateOnly `json:"valid_from"`
	ValidTill      NullDateOnly `json:"valid_till"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`
}

type UserMember struct {
	User                    `gorm:"embedded"`
	LastActivityIndicatedAt time.Time  `json:"last_activity_indicated_at" gorm:"column:last_activity_indicated_at"`
	Password                string     `json:"password"`
	Status                  uint8      `json:"status"`
	Username                string     `json:"username"`
	LastReminderSentAt      *time.Time `json:"last_reminder_sent_at" gorm:"column:last_reminder_sent_at"`
	UserInactivatedAt       *time.Time `json:"user_inactivated_at" gorm:"column:user_inactivated_at"`
}

func (UserMember) TableName() string {
	return "users"
}

func (u *UserMember) SetID(id uint) {
	u.ID = id
}
func (k *UserMember) SetUserStatus(status uint8) {
	k.Status = status
}

func (a *UserMember) GetUserStatus() uint8 {
	return a.Status
}

func (a *UserMember) SetPassword(password string) {
	a.Password = password
}

func (a *UserMember) GetPassword() string {
	return a.Password
}

func (u *User) GetID() uint {
	return u.ID
}

// func (u *User) GetUsername() string {
// 	return u.Username
// }

func (u *User) GetFirstName() string {
	return u.FirstName
}

func (u *User) GetLastName() string {
	return u.LastName
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetMobile() uint64 {
	return u.Mobile
}
func (u *User) GetLastPassChange() *time.Time {
	return u.LastPassChange
}
func (u *User) GetCreatedAt() time.Time {
	return u.CreatedAt
}

func (u *User) GetLastLogin() *time.Time {
	return u.LastLogin
}

func (u *User) GetUpdatedAt() time.Time {
	return u.UpdatedAt
}

func (u *User) SetLastPassChange(t *time.Time) {
	u.LastPassChange = t
}
func (u *User) SetLastLogin(t *time.Time) {
	u.LastLogin = t
}
func (u *User) SetCreatedAt(t time.Time) {
	u.CreatedAt = t
}
func (u *User) SetUpdatedAt(t time.Time) {
	u.UpdatedAt = t
}

func (u *User) SetEmail(email string) {
	u.Email = email
}

func (u *User) SetMobile(mobile uint64) {
	u.Mobile = mobile
}

func (u *User) SetFirstName(firstName string) {
	u.FirstName = firstName
}

func (u *User) SetLastName(lastName string) {
	u.LastName = lastName
}

func (u *User) GetValidFrom() NullDateOnly {
	return u.ValidFrom
}

func (a *UserMember) GetLastActivityIndicatedAt() time.Time {
	return time.Now()
}

func (a *UserMember) GetUsername() string {
	return a.Username
}

func (k *UserMember) GetValidFrom() NullDateOnly {
	return k.ValidFrom
}

func (k *UserMember) GetValidTill() NullDateOnly {
	return k.ValidTill
}

func (k *UserMember) GetLastReminderSentAt() *time.Time {
	return k.LastReminderSentAt
}

func (k *UserMember) GetUserInactivatedAt() *time.Time {
	return k.UserInactivatedAt
}

func (u *User) SetValidFrom(timeToSet time.Time) {
	u.ValidFrom = NullDateOnly{
		Date:  DateOnly(timeToSet),
		Valid: true,
	}
}

func (u *User) EnsureValidFromIsSet() {
	currentValidFrom := u.GetValidFrom()
	if !currentValidFrom.Valid || time.Time(currentValidFrom.Date).IsZero() {
		currTime := time.Now()
		u.SetValidFrom(currTime) // Set ValidFrom to current date/time
	}
}
