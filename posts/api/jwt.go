package api

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("my_secret_key")

//AuthClaims represents the claims in the access token
type AuthClaims struct {
	Email         string
	EmailVerified bool
	UserID        string
	jwt.StandardClaims
}

func ValidateToken(tokenString string) (jwt.MapClaims, error) {

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("could not parse claims")
	}
}
