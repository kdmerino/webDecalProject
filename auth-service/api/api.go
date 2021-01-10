package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	verifyTokenSize = 6
	resetTokenSize  = 6
)

// RegisterRoutes initializes the api endpoints and maps the requests to specific functions
func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/auth/signup", signup).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/signin", signin).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/logout", logout).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/verify", verify).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/sendreset", sendReset).Methods(http.MethodPut, http.MethodOptions)
	router.HandleFunc("/api/auth/resetpw", resetPassword).Methods(http.MethodPut, http.MethodOptions)

	// Load sendgrid credentials
	err := godotenv.Load()
	if err != nil {
		return err
	}

	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)
	return nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:80")
	w.Header().Set("Access-Control-Allow-Headers", "content-type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if (*r).Method == "OPTIONS" {
		return
	}

	//Obtain the credentials from the request body
	userInfo := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userName, userEmail, userPass := userInfo.Username, userInfo.Email, userInfo.Password

	//Check if the username already exists
	var exists bool
	err = DB.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE username = ?)", userName).Scan(&exists)
	//Check for error
	if err != nil {
		http.Error(w, errors.New("error checking if username exists").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	//Check boolean returned from query
	if exists == true {
		http.Error(w, errors.New("this username is taken").Error(), http.StatusConflict)
		return
	}

	//Check if the email already exists
	err = DB.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE email = ?)", userEmail).Scan(&exists)
	//Check for error
	if err != nil {
		http.Error(w, errors.New("error checking if email exists").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	//Check boolean returned from query
	if exists {
		http.Error(w, errors.New("Your email already has an account in use").Error(), http.StatusConflict)
		return
	}

	//Hash the password using bcrypt and store the hashed password in a variable
	hash, err := bcrypt.GenerateFromPassword([]byte(userPass), bcrypt.DefaultCost)
	//Check for errors during hashing process
	if err != nil {
		http.Error(w, errors.New("errors during hashing... aborting").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	//Create a new user UUID, convert it to string, and store it within a variable
	userUUID, _ := uuid.NewRandom()

	//Create new verification token with the default token size (look at GetRandomBase62 and our constants)
	userVT := GetRandomBase62(verifyTokenSize)
	//Store credentials in database
	_, err = DB.Query("INSERT INTO users VALUES (?, ?, ?, 0, NULL, ?, ?)", userName, userEmail, hash, userVT, userUUID)
	//Check for errors in storing the credentials
	if err != nil {
		http.Error(w, errors.New("error storing user credentials").Error(), http.StatusConflict)
		return
	}

	//Generate an access token, expiry dates are in Unix time
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userUUID.String(),
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	//Check for error in generating an access token
	if err != nil {
		http.Error(w, errors.New("error generating an access token").Error(), http.StatusConflict)
		return
	}

	//Set the cookie, name it "access_token"
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: accessExpiresAt,
		// Leave these next three values commented for now
		// Secure: true,
		// HttpOnly: true,
		// SameSite: http.SameSiteNoneMode,
		Path: "/",
	})

	//Generate refresh token
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userUUID.String(),
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	if err != nil {
		http.Error(w, errors.New("error creating refreshToken").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	//set the refresh token ("refresh_token") as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})

	// Send verification email
	err = SendEmail(userInfo.Email, "Email Verification", "user-signup.html", map[string]interface{}{"Token": userVT})
	if err != nil {
		http.Error(w, errors.New("error sending verification email").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	w.WriteHeader(201)
	return
}

func signin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:80")
	w.Header().Set("Access-Control-Allow-Headers", "content-type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if (*r).Method == "OPTIONS" {
		return
	}

	//Store the credentials in a instance of Credentials
	userInfo := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&userInfo)
	//Check for errors in storing credntials
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userName, userPass := userInfo.Username, userInfo.Password

	//Get the hashedPassword and userId of the user
	var hashedPassword, userID string
	err = DB.QueryRow("SELECT hashedPassword, userId FROM users WHERE username = ?", userName).Scan(&hashedPassword, &userID)
	// process errors associated with emails
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, errors.New("this email is not associated with an account").Error(), http.StatusNotFound)
		} else {
			http.Error(w, errors.New("error retrieving information with this email").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
		}
		return
	}

	// Check if hashed password matches the one corresponding to the email
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(userPass))
	//Check error in comparing hashed passwords
	if err != nil {
		http.Error(w, errors.New("wrong password associated with this email").Error(), http.StatusInternalServerError)
		return
	}
	//Generate an access token  and set it as a cookie (Look at signup and feel free to copy paste!)
	//Generate an access token, expiry dates are in Unix time
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	//Check for error in generating an access token
	if err != nil {
		http.Error(w, errors.New("error generating an access token").Error(), http.StatusConflict)
		return
	}
	//Set the cookie, name it "access_token"
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: accessExpiresAt,
		// Leave these next three values commented for now
		// Secure: true,
		// HttpOnly: true,
		// SameSite: http.SameSiteNoneMode,
		Path: "/",
	})

	//Generate a refresh token and set it as a cookie (Look at signup and feel free to copy paste!)
	//Generate refresh token
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	if err != nil {
		http.Error(w, errors.New("error creating refreshToken").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	//set the refresh token ("refresh_token") as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})
	w.WriteHeader(200)
	return
}

func logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:80")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if (*r).Method == "OPTIONS" {
		return
	}

	// logging out causes expiration time of cookie to be set to now

	//Set the access_token and refresh_token to have an empty value and set their expiration date to anytime in the past
	var expiresAt = time.Now()
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Expires: expiresAt})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Expires: expiresAt})
	w.WriteHeader(200)
	return
}

func verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "localhost:80")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if (*r).Method == "OPTIONS" {
		return
	}

	token, ok := r.URL.Query()["token"]
	// check that valid token exists
	if !ok || len(token[0]) < 1 {
		http.Error(w, errors.New("Url Param 'token' is missing").Error(), http.StatusInternalServerError)
		log.Print(errors.New("Url Param 'token' is missing").Error())
		return
	}

	//Obtain the user with the verifiedToken from the query parameter and set their verification status to the integer "1"
	_, err := DB.Exec("UPDATE users SET verified = 1 WHERE verifiedToken = ?", token[0])

	//Check for errors in executing the previous query
	if err != nil {
		http.Error(w, errors.New("error attempting to verify token").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	w.WriteHeader(400)
	return
}

func sendReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "localhost:80")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if (*r).Method == "OPTIONS" {
		return
	}

	//Get the email from the body (decode into an instance of Credentials)
	userInfo := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&userInfo)
	//check for errors decoding the object
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userEmail := userInfo.Email
	//check for other miscallenous errors that may occur
	//what is considered an invalid input for an email?
	if userEmail == "" {
		http.Error(w, errors.New("the email you entered is invalid").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	//generate reset token
	token := GetRandomBase62(resetTokenSize)

	//Obtain the user with the specified email and set their resetToken to the token we generated
	_, err = DB.Query("UPDATE users set resetToken = ? WHERE email = ?", token, userEmail)
	//Check for errors executing the queries
	if err != nil {
		http.Error(w, errors.New("email not found").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	// Send verification email
	err = SendEmail(userInfo.Email, "BearChat Password Reset", "password-reset.html", map[string]interface{}{"Token": token})
	if err != nil {
		http.Error(w, errors.New("error sending verification email").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	return
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "localhost:80")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if (*r).Method == "OPTIONS" {
		return
	}

	//get token from query params
	token := r.URL.Query().Get("token")

	//get the username, email, and password from the body
	userInfo := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&userInfo)
	//check for errors decoding the object
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	username, email, userPass := userInfo.Username, userInfo.Email, userInfo.Password

	if len(username) == 0 {
		http.Error(w, errors.New("invalid user name").Error(), http.StatusBadRequest)
		return
	}
	if len(email) == 0 {
		http.Error(w, errors.New("invalid email").Error(), http.StatusBadRequest)
		return
	}
	if len(userPass) == 0 {
		http.Error(w, errors.New("invalid password").Error(), http.StatusBadRequest)
		return
	}

	var exists bool
	//check if the username and token pair exist
	err = DB.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE username = ? AND resetToken = ?)", username, token).Scan(&exists)
	//Check for errors executing the query
	if err != nil {
		http.Error(w, errors.New("error checking if email exists").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	//Check exists boolean. Call an error if the username-token pair doesn't exist
	if !exists {
		http.Error(w, errors.New("error this token does not match the given username").Error(), http.StatusConflict)
		return
	}

	//Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(userPass), bcrypt.DefaultCost)
	//Check for errors in hashing  new password
	if err != nil {
		http.Error(w, errors.New("errors during hashing... aborting").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	//input new password and clear the reset token (set the token equal to empty string)
	_, err = DB.Exec("UPDATE users SET hashedPassword = ?, resetToken = ? WHERE username = ?", hash, "", username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err.Error())
	}

	//put the user in the redis cache to invalidate all current sessions (NOT IN SCOPE FOR PROJECT), leave this comment for future reference

	return
}
