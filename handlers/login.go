package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	// "os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type JWTClaims struct {
	UserID       string                 `json:"user_id"`
	Role         string                 `json:"role"`
	HasuraClaims map[string]interface{} `json:"https://hasura.io/jwt/claims"` // Add Hasura claims
	jwt.StandardClaims
}

// Your secret key
// var jwtSecret = []byte(os.Getenv("JWTSECRET"))
var jwtSecret = []byte("my_very_secure_secret_key_1234567890")

// var jwtSecret = os.Getenv("JWTSECRET")

// smtpPassword := os.Getenv("SMTP_PASSWORD")
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	var actionPayload struct {
		Input struct {
			Object loginArgs `json:"object"`
		} `json:"input"`
	}

	err = json.Unmarshal(reqBody, &actionPayload)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	loginPayload := actionPayload.Input.Object

	result, err := login(loginPayload)
	if err != nil {
		errorObject := GraphQLError{
			Message: err.Error(),
		}
		errorBody, _ := json.Marshal(errorObject)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(errorBody)
		return
	}

	// Generate JWT including the user ID and role
	token, err := generateJWT(result.UserID, result.Role)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	response := struct {
		UserID string `json:"user_id"`
		Token  string `json:"token"`
		Role   string `json:"role"`
	}{
		UserID: result.UserID,
		Token:  token,
		Role:   result.Role,
	}
	fmt.Printf("token is %v\n", token)
	fmt.Printf("role is %v\n", result.Role)

	data, _ := json.Marshal(response)
	w.Write(data)
}

func login(args loginArgs) (response userOutput, err error) {
	hasuraResponse, err := executeLogin(map[string]interface{}{
		"email": args.Email,
	})
	if err != nil {
		return
	}

	if len(hasuraResponse.Errors) != 0 {
		err = errors.New(hasuraResponse.Errors[0].Message)
		return
	}
	if len(hasuraResponse.Data.User) == 0 {
		err = errors.New("invalid credentials")
		return
	}

	user := hasuraResponse.Data.User[0]

	isValid := checkPasswordHash(args.Password, user.Password)
	if !isValid {
		err = errors.New("invalid credentials")
		return
	}

	response = user
	return
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Function to generate JWT token with Hasura claims
func generateJWT(userID, role string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Role:   role,
		HasuraClaims: map[string]interface{}{
			"x-hasura-default-role":  role,
			"x-hasura-allowed-roles": []string{"user", "admin"},
			"x-hasura-user-id":       userID,
			"x-hasura-org-id":        "456", // Replace with dynamic org ID if needed
			"x-hasura-custom":        "custom-value",
		},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			Issuer:    "cinema_app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	fmt.Println("lllllllllllll", jwtSecret)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
func executeLogin(variables map[string]interface{}) (response GraphQLResponse, err error) {
	query := `query ($email: String!) {
        user(where: {email: {_eq: $email}}) {
            user_id
            password
            role
        }
    }`

	reqBody := GraphQLRequest{
		Query:     query,
		Variables: variables,
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	// Create HTTP request with x-hasura-admin-secret header
	req, err := http.NewRequest("POST", "http://localhost:8080/v1/graphql", bytes.NewBuffer(reqBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-hasura-admin-secret", "your_admin_secret_here") // replace with your actual secret

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
		return
	}

	err = json.Unmarshal(respBytes, &response)
	return
}

// func executeLogin(variables map[string]interface{}) (response GraphQLResponse, err error) {
// 	query := `query ($email: String!) {
//         user(where: {email: {_eq: $email}}) {
//             user_id
//             password
//             role
//         }
//     }`

// 	reqBody := GraphQLRequest{
// 		Query:     query,
// 		Variables: variables,
// 	}
// 	reqBytes, err := json.Marshal(reqBody)
// 	if err != nil {
// 		return
// 	}

// 	resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))

// 	if err != nil {
// 		return
// 	}
// 	defer resp.Body.Close()

// 	respBytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return
// 	}

// 	if resp.StatusCode != http.StatusOK {
// 		err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
// 		return
// 	}

// 	err = json.Unmarshal(respBytes, &response)
// 	return
// }
