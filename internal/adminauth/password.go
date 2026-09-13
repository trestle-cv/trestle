package adminauth

import (
	"errors"
	"fmt"

	coreauth "github.com/gantry-tools/gantry-core/auth"
)

const MinPasswordLength = 7

func hashPassword(password string) (string, error) {
	if len([]rune(password)) < MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	return coreauth.HashPassword(password)
}

func verifyPassword(encoded, password string) bool {
	return coreauth.VerifyPassword(encoded, password)
}

var errInvalidCredentials = errors.New("invalid credentials")
