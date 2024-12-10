package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
)

type ActionPayload struct {
	SessionVariables map[string]interface{} `json:"session_variables"`
	Input            signupArgs             `json:"input"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

type GraphQLRequest struct {
	Query     string      `json:"query"`
	Variables interface{} `json:"variables"`
}

type GraphQLData struct {
	Insert_user_one signupOutput `json:"insert_user_one"`
	User            []userOutput `json:"user"` // Changed to array
}

type GraphQLResponse struct {
	Data   GraphQLData    `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

type signupArgs struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginArgs struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type signupOutput struct {
	UserID string `json:"user_id"`
}

type userOutput struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
	Role     string `json:"role"` // Add role here
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	var actionPayload ActionPayload
	err = json.Unmarshal(reqBody, &actionPayload)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	result, err := signup(actionPayload.Input)
	if err != nil {
		errorObject := GraphQLError{
			Message: err.Error(),
		}
		errorBody, _ := json.Marshal(errorObject)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errorBody)
		return
	}

	data, _ := json.Marshal(result)
	w.Write(data)
}

func signup(args signupArgs) (response signupOutput, err error) {
	hashedPassword, err := hashPassword(args.Password)
	if err != nil {
		return
	}

	variables := map[string]interface{}{
		"username": args.Username,
		"email":    args.Email,
		"password": hashedPassword,
	}

	hasuraResponse, err := executeSignup(variables)
	if err != nil {
		return
	}

	if len(hasuraResponse.Errors) != 0 {
		err = errors.New(hasuraResponse.Errors[0].Message)
		return
	}

	response = hasuraResponse.Data.Insert_user_one
	return
}
func executeSignup(variables map[string]interface{}) (response GraphQLResponse, err error) {
	query := `mutation ($username: String!, $email: String!, $password: String!) {
        insert_user_one(object: {username: $username, email: $email, password: $password}) {
            user_id
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

	// Create an HTTP POST request with x-hasura-admin-secret header
	req, err := http.NewRequest("POST", "http://localhost:8080/v1/graphql", bytes.NewBuffer(reqBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-hasura-admin-secret", "your_admin_secret_here") // replace with your actual admin secret

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

// func executeSignup(variables map[string]interface{}) (response GraphQLResponse, err error) {
// 	query := `mutation ($username: String!, $email: String!, $password: String!) {
//         insert_user_one(object: {username: $username, email: $email, password: $password}) {
//             user_id
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
// 	if err != nil {
// 		return
// 	}

// 	return
// }

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
