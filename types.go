package main

import (
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/golang-jwt/jwt/v5"
)

type TokenResponse struct {
	Token string `json:"token"`
}

type RefreshJWTClaims struct {
	Id int `json:"id"`
	jwt.RegisteredClaims
}

type AuthJWTClaims struct {
	Id int `json:"id"`
	jwt.RegisteredClaims
}

type ServerJWTClaims struct {
	Id int `json:"id"`
	jwt.RegisteredClaims
}

type ClientJWTClaims struct {
	Id int `json:"id"`
	jwt.RegisteredClaims
}

type RefreshResponse struct {
	Token string `json:"token"`
}

type ProfileResponse struct {
	Token string `json:"token"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Id    int64  `json:"id"`
	Token string `json:"token"`
}

type UpdateRequest struct {
	Score int `json:"score"`
}

type TransferRequest struct {
	ToAccount int `json:"toAccount"`
	Amount    int `json:"amount"`
}

type CreateAccountRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Account struct {
	ID                int       `json:"id"`
	Username          string    `json:"username"`
	Email             string    `json:"email"`
	EncryptedPassword string    `json:"-"`
	Exp               int       `json:"exp"`
	Currency          int       `json:"currency"`
	CreatedAt         time.Time `json:"createdAt"`
}

func (a *Account) ValidatePassword(pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(pw)) == nil
}

func NewAccount(username, email, password string) (*Account, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return &Account{
		Username:          username,
		Email:             email,
		CreatedAt:         time.Now().UTC(),
		EncryptedPassword: string(encpw),
	}, nil
}
