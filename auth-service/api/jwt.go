package api

import (
	"errors"
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	//DefaultAccessJWTExpiry is the default access token duration
	DefaultAccessJWTExpiry = 01 * 1440 * time.Minute // refresh every 01 days
	//DefaultRefreshJWTExpiry is the default refresh token duration
	DefaultRefreshJWTExpiry = 30 * 1440 * time.Minute // refresh every 30 days
	defaultJWTIssuer        = "CalChat"
	jwtKey                  = []byte("my_secret_key")
)

//AuthClaims represents the claims in the access token
type AuthClaims struct {
	UserID string
	jwt.StandardClaims
}

func setClaims(claims AuthClaims) (tokenString string, Error error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}

func getClaims(tokenString string) (claims AuthClaims, Error error) {
	claims = AuthClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return AuthClaims{}, err
	}
	if !token.Valid {
		return AuthClaims{}, errors.New("The given token is not valid")
	}
	return claims, nil
}

//GetRandomBase62 returns a string of random base62 characters
func GetRandomBase62(length int) string {
	const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rand.Seed(time.Now().Unix())
	r := make([]byte, length)
	for i := range r {
		r[i] = base62[rand.Intn(len(base62))]
	}
	return string(r)
}