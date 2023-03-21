package main

import (
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var clientSecret = []byte(os.Getenv("JWT_CLIENT_SECRET"))
var serverSecret = []byte(os.Getenv("JWT_SERVER_SECRET"))
var authSecret = []byte(os.Getenv("JWT_AUTH_SECRET"))
var refreshSecret = []byte(os.Getenv("JWT_REFRESH_SECRET"))

func PrintSecrets() {
	fmt.Printf("client: %s\n", string(clientSecret))
	fmt.Printf("server: %s\n", string(serverSecret))
	fmt.Printf("auth: %s\n", string(authSecret))
	fmt.Printf("refresh: %s\n", string(refreshSecret))
}

func createClientJWT(ID int) (string, error) {
	claims := &ClientJWTClaims{
		Id: ID,
	}

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Second))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(clientSecret)
}

func createServerJWT(ID int) (string, error) {
	claims := &ServerJWTClaims{
		Id: ID,
	}

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(serverSecret)
}

func createAuthJWT(ID int) (string, error) {
	claims := &AuthJWTClaims{
		Id: ID,
	}

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Second))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(authSecret)
}

func createRefreshJWT(account *Account) (string, error) {
	claims := &RefreshJWTClaims{
		Id: account.ID,
	}

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshSecret)
}

func validateServerJWT(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, &ServerJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
		}
		return serverSecret, nil
	})
}

func validateClientJWT(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, &ClientJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
		}
		return clientSecret, nil
	})
}

func validateAuthJWT(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
		}
		return authSecret, nil
	})
}

func validateRefreshJWT(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, &RefreshJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
		}
		return refreshSecret, nil
	})
}
