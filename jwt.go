package main

import (
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func createAuthJWT(ID int) (string, error) {
	claims := &AuthJWTClaims{
		Id: ID,
	}

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	secret := os.Getenv("JWT_AUTH_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func createRefreshJWT(account *Account) (string, error) {
	claims := &RefreshJWTClaims{
		Id: account.ID,
	}

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	secret := os.Getenv("JWT_REFRESH_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func validateAuthJWT(token string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_AUTH_SECRET")
	return jwt.ParseWithClaims(token, &AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	//if claims, ok := jwtToken.Claims.(*AuthJWTClaims); ok && jwtToken.Valid {
	//fmt.Printf("%v %v", claims.Foo, claims.RegisteredClaims.Issuer)
	//} else {
	//fmt.Println(err)
	//}

	//return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

	//if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	//return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
	//}

	//return []byte(secret), nil
	//})

}

func validateRefreshJWT(token string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_REFRESH_SECRET")
	return jwt.ParseWithClaims(token, &RefreshJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	//return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

	//if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	//return nil, fmt.Errorf("Unespected signing method: %v", token.Header["alg"])
	//}

	//return []byte(secret), nil
	//})
}
