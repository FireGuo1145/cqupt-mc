package main

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

const usernameKeyIndex = "idx_users_username_key"

// normalizeUsername follows the accepted username alphabet (ASCII letters and
// digits), so Unicode case-folding differences cannot produce ambiguous keys.
func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// BeforeSave keeps the canonical key in sync for all GORM-created User rows.
// Partial map updates that rename an account also set username_key explicitly.
func (u *User) BeforeSave(_ *gorm.DB) error {
	key := normalizeUsername(u.Username)
	u.UsernameKey = &key
	return nil
}

func usernameReserved(db *gorm.DB, username string, exceptUserID uint) (bool, error) {
	key := normalizeUsername(username)
	users := db.Model(&User{}).Where("username_key = ?", key)
	if exceptUserID != 0 {
		users = users.Where("id <> ?", exceptUserID)
	}
	var count int64
	if err := users.Count(&count).Error; err != nil {
		return false, err
	}
	if count != 0 {
		return true, nil
	}
	if err := db.Model(&ManualRegistration{}).Where("active_username_key = ?", key).Count(&count).Error; err != nil {
		return false, err
	}
	return count != 0, nil
}

func studentIDReserved(db *gorm.DB, studentID string, exceptUserID uint) (bool, error) {
	users := db.Model(&User{}).Where("student_id = ?", studentID)
	if exceptUserID != 0 {
		users = users.Where("id <> ?", exceptUserID)
	}
	var count int64
	if err := users.Count(&count).Error; err != nil {
		return false, err
	}
	if count != 0 {
		return true, nil
	}
	if err := db.Model(&ManualRegistration{}).Where("active_student_key = ?", studentID).Count(&count).Error; err != nil {
		return false, err
	}
	return count != 0, nil
}

// migrateUsernameKeys backfills existing rows before enforcing a unique key.
// If legacy accounts already collide case-insensitively, startup fails with a
// clear message rather than silently renaming a player's account.
func migrateUsernameKeys(db *gorm.DB) error {
	if err := db.Exec("UPDATE users SET username_key = LOWER(username) WHERE username_key IS NULL OR username_key = ''").Error; err != nil {
		return fmt.Errorf("backfill canonical usernames: %w", err)
	}
	var duplicates []struct {
		Key   string `gorm:"column:username_key"`
		Count int64  `gorm:"column:count"`
	}
	if err := db.Model(&User{}).
		Select("username_key, COUNT(*) AS count").
		Group("username_key").
		Having("COUNT(*) > ?", 1).
		Limit(1).
		Scan(&duplicates).Error; err != nil {
		return fmt.Errorf("check canonical usernames: %w", err)
	}
	if len(duplicates) != 0 {
		return fmt.Errorf("existing usernames collide ignoring case (%q, %d accounts); rename conflicting accounts before restarting", duplicates[0].Key, duplicates[0].Count)
	}
	if !db.Migrator().HasIndex(&User{}, usernameKeyIndex) {
		if err := db.Exec("CREATE UNIQUE INDEX " + usernameKeyIndex + " ON users (username_key)").Error; err != nil {
			return fmt.Errorf("create case-insensitive username index: %w", err)
		}
	}
	return nil
}
