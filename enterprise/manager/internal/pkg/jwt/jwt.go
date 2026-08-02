package jwt

import (
	"errors"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID         string `json:"uid"`
	OrganizationID string `json:"org"`
	Role           string `json:"role"`
	Email          string `json:"email"`
	jwtlib.RegisteredClaims
}

func IssueAccess(secret, userID, orgID, role, email string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		Email:          email,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now()),
			Issuer:    "cybersec-manager",
		},
	}
	return jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func ParseAccess(secret, token string) (Claims, error) {
	var claims Claims
	parsed, err := jwtlib.ParseWithClaims(token, &claims, func(t *jwtlib.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !parsed.Valid {
		return claims, errors.New("invalid token")
	}
	return claims, nil
}
