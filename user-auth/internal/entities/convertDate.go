package entities

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// DateOnly is the custom type for handling date-only values
type DateOnly time.Time
type NullDateOnly struct {
	Date  DateOnly
	Valid bool // Valid indicates whether the value is NULL or not
}

// Scan implements the sql.Scanner interface for NullDateOnly.
// to convert a database value into custom NullDateOnly type when fetching data from the database.
func (nd *NullDateOnly) Scan(value interface{}) error {
	if value == nil {
		nd.Valid = false
		return nil
	}

	// If value is of type time.Time (expected from the database)
	if t, ok := value.(time.Time); ok {
		nd.Date = DateOnly(t)
		nd.Valid = true
		return nil
	}

	// If value is of type string (which could be a date string in the database)
	if str, ok := value.(string); ok {
		t, err := time.Parse("2006-01-02", str)
		if err != nil {
			return fmt.Errorf("failed to parse date: %v", err)
		}
		nd.Date = DateOnly(t)
		nd.Valid = true
		return nil
	}

	return fmt.Errorf("failed to scan NullDateOnly: expected time.Time or string but got %T", value)
}

// Value implements the driver.Valuer interface for NullDateOnly.
// to store NullDateOnly values back into the database.
func (nd NullDateOnly) Value() (driver.Value, error) {
	if !nd.Valid {
		return nil, nil // Represents NULL in the database
	}

	// Convert the DateOnly type to time.Time and return the value in the appropriate format
	return time.Time(nd.Date).Format("2006-01-02"), nil
}

// Optional: MarshalJSON to handle JSON serialization.
func (nd NullDateOnly) MarshalJSON() ([]byte, error) {
	if !nd.Valid {
		return []byte("null"), nil
	}
	return []byte(`"` + time.Time(nd.Date).Format("2006-01-02") + `"`), nil
}

// Optional: UnmarshalJSON to handle JSON deserialization.
func (nd *NullDateOnly) UnmarshalJSON(b []byte) error {
	// Parse date string
	str := string(b)
	if str == "null" {
		nd.Valid = false
		return nil
	}
	parsedTime, err := time.Parse(`"2006-01-02"`, str)
	if err != nil {
		return err
	}
	nd.Date = DateOnly(parsedTime)
	nd.Valid = true
	return nil
}
