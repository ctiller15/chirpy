package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestHashAndCheck(t *testing.T) {
	tests := map[string]struct {
		input string
	}{
		"standard": {
			input: "passwordButABitLongerForSafety",
		},
		"complex": {
			input: "1337password7331",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hash, err := HashPassword(test.input)
			assert.Nil(t, err)

			err = CheckPasswordHash(test.input, hash)
			assert.Nil(t, err)
		})
	}
}

func TestValidateJWT(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		secret := "test_secret_key"
		userID := uuid.New()
		expiresIn := time.Minute

		tokenString, err := MakeJWT(userID, secret, expiresIn)
		if err != nil {
			t.Errorf("Failed to create JWT: %v", err)
		}

		decodedID, err := ValidateJWT(tokenString, secret)
		if err != nil || userID != decodedID {
			t.Errorf("Expected %v, got %v (error: %v)", userID, decodedID, err)
		}
	})

	t.Run("Invalid secret", func(t *testing.T) {
		secret := "correct_test_key"
		userID := uuid.New()
		expiresIn := time.Minute

		tokenString, err := MakeJWT(userID, secret, expiresIn)
		if err != nil {
			t.Errorf("failed to create jwt: %v", err)
		}

		_, err = ValidateJWT(tokenString, "fakeSecret")
		if err == nil {
			t.Errorf("expected error due to incorrect secret")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		userID := uuid.New()
		secret := "test_secret_expired"
		expiredToken, _ := MakeJWT(userID, secret, -time.Minute)
		_, err := ValidateJWT(expiredToken, secret)
		if err == nil {
			t.Error("expected an error for expired token")
		}
	})
}

func TestGetBearerToken(t *testing.T) {
	t.Run("Happy path", func(t *testing.T) {
		newHeader := make(http.Header)
		newHeader.Add("Authorization", "Bearer 123456")

		result, err := GetBearerToken(newHeader)
		if err != nil {
			t.Errorf("error: %v", err)
		}

		assert.Equal(t, result, "123456")
	})
}
