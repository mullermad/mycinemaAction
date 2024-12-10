package handlers

import (
	"bytes"
	"encoding/json"

	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid" // Import the UUID package
	"github.com/joho/godotenv"
)

// Struct to match the Chapa API response format
type ChapaResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	Data    struct {
		CheckoutURL string `json:"checkout_url"`
	} `json:"data"`
}

// Struct for receiving payment details from the GraphQL request
type PaymentInput struct {
	PhoneNumber string `json:"phoneNumber"`
	Amount      string `json:"amount"`
}

type Payment struct {
	Arg1 PaymentInput `json:"arg1"` // This corresponds to the GraphQL input format
}

// Struct for webhook notification from Chapa
type WebhookNotification struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    struct {
		TxRef  string `json:"tx_ref"`
		Amount string `json:"amount"`
	} `json:"data"`
}

// Struct for verification response
type VerificationResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	Data    struct {
		FirstName     string       `json:"first_name"`
		LastName      string       `json:"last_name"`
		Email         string       `json:"email"`
		PhoneNumber   string       `json:"phone_number"`
		Currency      string       `json:"currency"`
		Amount        int          `json:"amount"` // Adjust type as needed
		Charge        *interface{} `json:"charge"` // Pointer for optional fields
		Mode          string       `json:"mode"`
		Method        *string      `json:"method"` // Pointer for optional fields
		Type          string       `json:"type"`
		Status        string       `json:"status"`
		Reference     *string      `json:"reference"` // Pointer for optional fields
		TxRef         string       `json:"tx_ref"`
		Customization struct {
			Title       string  `json:"title"`
			Description string  `json:"description"`
			Logo        *string `json:"logo"`
		} `json:"customization"`
		Meta struct {
			HideReceipt bool `json:"hide_receipt"`
		} `json:"meta"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	} `json:"data"`
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

// PaymentsHandler handles payment initialization
func PaymentsHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read and log the entire request body for debugging
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	log.Printf("Received request body: %s", bodyBytes)

	// Parse the incoming request body
	var hasuraRequest struct {
		Action struct {
			Name string `json:"name"`
		} `json:"action"`
		Input Payment `json:"input"`
	}
	err = json.Unmarshal(bodyBytes, &hasuraRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Error decoding JSON: %v", err)
		return
	}

	// Log the decoded payment input
	log.Printf("Decoded payment input: %+v", hasuraRequest.Input.Arg1)

	// Validate required fields
	if hasuraRequest.Input.Arg1.Amount == "" {
		http.Error(w, `{"error": "Amount is required"}`, http.StatusBadRequest)
		return
	}

	if hasuraRequest.Input.Arg1.PhoneNumber == "" {
		http.Error(w, `{"error": "Phone number is required"}`, http.StatusBadRequest)
		return
	}

	// Generate a dynamic tx_ref using UUID
	txRef := "chewatatest-" + uuid.New().String()

	url := "https://api.chapa.co/v1/transaction/initialize"

	// Prepare payload with dynamic tx_ref and user inputs
	payload := map[string]interface{}{
		"amount":       hasuraRequest.Input.Arg1.Amount,
		"currency":     "ETB",
		"email":        "mulukendemis44@gmail.com",
		"first_name":   "Muluken",
		"last_name":    "Demis",
		"phone_number": hasuraRequest.Input.Arg1.PhoneNumber,
		"tx_ref":       txRef,
		"callback_url": "https://webhook.site/077164d6-29cb-40df-ba29-8a00e59a7e60",
		"return_url":   "http://localhost:3000/successfulpay",
		"customization": map[string]string{
			"title":       "Payment",
			"description": "I love online payments",
		},
		"meta": map[string]bool{
			"hide_receipt": true,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}

	// Create a new HTTP client and request
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Load the Chapa API key from the environment variable
	chapaKey := os.Getenv("CHAPA_API_KEY")
	if chapaKey == "" {
		http.Error(w, "CHAPA_API_KEY is not set in the environment", http.StatusInternalServerError)
		return
	}
	log.Printf("chapakey: %+v", chapaKey)

	// Set request headers
	req.Header.Add("Authorization", "Bearer "+chapaKey)
	req.Header.Add("Content-Type", "application/json")

	// Send the request
	res, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error sending request", http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	// Read the response
	responseBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusInternalServerError)
		return
	}

	log.Println("Chapa API Response:", string(responseBody))

	// Unmarshal the response into the ChapaResponse struct
	var chapaResponse ChapaResponse
	err = json.Unmarshal(responseBody, &chapaResponse)
	if err != nil {
		http.Error(w, "Error unmarshalling response", http.StatusInternalServerError)
		return
	}

	// Check if the response status is "success"
	if chapaResponse.Status == "success" {
		// Call the verification function
		verificationResponse, err := VerifyTransaction(txRef)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check the verification response status
		if verificationResponse.Status == "success" {
			log.Printf("Verification Response after verification: %v", verificationResponse) // Log verification response for debugging

			response := map[string]interface{}{
				"message":      chapaResponse.Message,
				"tx_ref":       txRef,
				"checkoutUrl":  chapaResponse.Data.CheckoutURL,
				"verification": verificationResponse,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			http.Error(w, "Verification failed", http.StatusBadGateway)
			log.Printf("Verification Response: %v", verificationResponse) // Log verification response for debugging
		}
	} else {
		http.Error(w, "Error in payment initialization", http.StatusBadGateway)
		log.Printf("Response: %s", string(responseBody)) // Log full response for debugging
	}

}

// VerifyTransaction verifies the transaction with Chapa
func VerifyTransaction(txRef string) (VerificationResponse, error) {
	url := "https://api.chapa.co/v1/transaction/verify/" + txRef
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return VerificationResponse{}, err
	}

	chapaKey := os.Getenv("CHAPA_API_KEY")
	// if chapaKey == "" {
	// 	return nil, errors.New("CHAPA_API_KEY is not set in the environment")
	// }

	// Set request headers
	req.Header.Add("Authorization", "Bearer "+chapaKey)
	req.Header.Add("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return VerificationResponse{}, err
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return VerificationResponse{},
			fmt.Errorf("failed to verify transaction: %s", resp.Status)
	}

	var verificationResponse VerificationResponse
	if err := json.NewDecoder(resp.Body).Decode(&verificationResponse); err != nil {
		return VerificationResponse{}, err
	}

	return verificationResponse, nil
}
