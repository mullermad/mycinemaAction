package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
// "fmt"
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
		"callback_url": "https://webhook.site/your-callback-url",
		"return_url":   "http://localhost:3000",
		"customization": map[string]string{
			"title":       "Payment",
			"description": "I love online payments",
		},
		"meta": map[string]bool{
			"hide_receipt": true,
		},
	}

	// Marshal the payload into JSON
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
		response := map[string]interface{}{
			"message":     chapaResponse.Message,
			"tx_ref":      txRef,
			"checkoutUrl": chapaResponse.Data.CheckoutURL,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Error in payment initialization", http.StatusBadGateway)
		log.Printf("Response: %s", string(responseBody)) // Log full response for debugging
	}
}



// WebhookHandler handles webhook notifications from Chapa
// func WebhookHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
// 	// Ensure the request method is POST
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Read and log the request body for debugging
// 	bodyBytes, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, "Error reading request body", http.StatusInternalServerError)
// 		return
// 	}
// 	log.Printf("Received webhook body: %s", bodyBytes)

// 	// Unmarshal the incoming webhook data
// 	var webhookResponse WebhookNotification
// 	err = json.Unmarshal(bodyBytes, &webhookResponse)
// 	if err != nil {
// 		http.Error(w, "Invalid webhook format", http.StatusBadRequest)
// 		log.Printf("Error decoding JSON: %v", err)
// 		return
// 	}

// 	// Log the webhook response
// 	log.Printf("Webhook Response: %+v", webhookResponse)

// 	// Handle payment verification based on the status
// 	if webhookResponse.Status == "success" {
// 		// Handle successful payment (update your database or application state)
// 		log.Printf("Payment successful for tx_ref: %s, amount: %s", webhookResponse.Data.TxRef, webhookResponse.Data.Amount)
// 		// Update your payment status in the database here
// 		w.WriteHeader(http.StatusOK) // Respond with 200 OK
// 		return
// 	} else {
// 		// Handle other statuses (failed, pending, etc.)
// 		log.Printf("Payment failed or pending for tx_ref: %s, status: %s", webhookResponse.Data.TxRef, webhookResponse.Status)
// 		w.WriteHeader(http.StatusBadRequest) // Respond with 400 Bad Request for failed or pending payments
// 		return
// 	}
// }
