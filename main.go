package main

// https://mycinemaaction.onrender.com/signup
import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"

	"github.com/mullermad/myserver/handlers"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello Muller, welcome to Go!")
}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/", helloHandler)
	router.HandleFunc("/signup", handlers.SignupHandler).Methods("POST")
	router.HandleFunc("/login", handlers.LoginHandler).Methods("POST")
	router.HandleFunc("/upload", handlers.UploadFileHandler)
	// Define routes for event triggers.
	// http.HandleFunc("/send_email", handleSignupEvent)
	router.HandleFunc("/send_email", handlers.HandleSignupEvent).Methods("POST")
	router.HandleFunc("/pay", handlers.PaymentsHandler).Methods("POST")
	// http.HandleFunc("/webhook", WebhookHandler)
	// router.HandleFunc("/webhook", handlers.WebhookHandler).Methods("POST")

	fmt.Println("Server is listening on port 5000...")
	log.Fatal(http.ListenAndServe(":5000", router))
	fmt.Println("Server is listening on port 5000...")

}

// type ActionPayload struct {
//     SessionVariables map[string]interface{} `json:"session_variables"`
//     Input            signupArgs             `json:"input"`
// }

// type GraphQLError struct {
//     Message string `json:"message"`
// }

// type GraphQLRequest struct {
//     Query     string      `json:"query"`
//     Variables interface{} `json:"variables"`
// }

// type GraphQLData struct {
//     Insert_user_one signupOutput `json:"insert_user_one"`
//     User            []userOutput `json:"user"` // Changed to array
// }

// type GraphQLResponse struct {
//     Data   GraphQLData    `json:"data,omitempty"`
//     Errors []GraphQLError `json:"errors,omitempty"`
// }

// type signupArgs struct {
//     Username string `json:"username"`
//     Email    string `json:"email"`
//     Password string `json:"password"`
// }

// type loginArgs struct {
//     Email    string `json:"email"`
//     Password string `json:"password"`
// }

// type signupOutput struct {
//     UserID string `json:"user_id"`
// }

// type userOutput struct {
//     UserID   string `json:"user_id"`
//     Password string `json:"password"`
//     Role     string `json:"role"` // Add role here
// }

// Define the structure for the incoming Hasura event payload.
// type HasuraEvent struct {
//     Event struct {
//         Data struct {
//             New struct {
//                 Email string `json:"email"`
//                 Username  string `json:"username"`
//             } `json:"new"`
//         } `json:"data"`
//     } `json:"event"`
// }
// // type JWTClaims struct {
// //     UserID string `json:"user_id"`
// //     jwt.StandardClaims
// // }
// type JWTClaims struct {
//     UserID string `json:"user_id"`
//     Role   string `json:"role"` // Add role field for Hasura
//     jwt.StandardClaims
// }

// var cloudinaryClient *cloudinary.Cloudinary

// func init() {
// // Load environment variables from the .env file
// // var err error
//     err := godotenv.Load()
//     if err != nil {
//         log.Fatal("Error loading .env file")
//     }

//      //Get Cloudinary credentials from environment variables
//      cloudName:= os.Getenv("CLOUDINARY_CLOUD_NAME")
//     apiKey:= os.Getenv("CLOUDINARY_API_KEY")
//     apiSecret:= os.Getenv("CLOUDINARY_API_SECRET")
//      if cloudName == "" || apiKey == "" || apiSecret == "" {
//         log.Fatal("Cloudinary environment variables are not set")
//     }
//     // fmt.Printf("cloudName %v apiKey %v apiSecret %v ",cloudName,apiKey,apiSecret)

//   cloudinaryClient, err = cloudinary.NewFromParams(cloudName, apiKey, apiSecret)

//         if err != nil {
//         log.Fatalf("Error initializing Cloudinary client: %v", err)
//     }
// }
// func signupHandler(w http.ResponseWriter, r *http.Request) {
//     w.Header().Set("Content-Type", "application/json")

//     reqBody, err := ioutil.ReadAll(r.Body)
//     if err != nil {
//         http.Error(w, "invalid payload", http.StatusBadRequest)
//         return
//     }

//     var actionPayload ActionPayload
//     err = json.Unmarshal(reqBody, &actionPayload)
//     if err != nil {
//         http.Error(w, "invalid payload", http.StatusBadRequest)
//         return
//     }

//     result, err := signup(actionPayload.Input)
//     if err != nil {
//         errorObject := GraphQLError{
//             Message: err.Error(),
//         }
//         errorBody, _ := json.Marshal(errorObject)
//         w.WriteHeader(http.StatusBadRequest)
//         w.Write(errorBody)
//         return
//     }

//     data, _ := json.Marshal(result)
//     w.Write(data)
// }

// Login handler to authenticate user and generate JWT
// func loginHandler(w http.ResponseWriter, r *http.Request) {
//     w.Header().Set("Content-Type", "application/json")

//     reqBody, err := ioutil.ReadAll(r.Body)
//     if err != nil {
//         http.Error(w, "invalid payload", http.StatusBadRequest)
//         return
//     }

//     var actionPayload struct {
//         Input struct {
//             Object loginArgs `json:"object"`
//         } `json:"input"`
//     }

//     err = json.Unmarshal(reqBody, &actionPayload)
//     if err != nil {
//         http.Error(w, "invalid payload", http.StatusBadRequest)
//         return
//     }

//     loginPayload := actionPayload.Input.Object

//     result, err := login(loginPayload)
//     if err != nil {
//         errorObject := GraphQLError{
//             Message: err.Error(),
//         }
//         errorBody, _ := json.Marshal(errorObject)
//         w.WriteHeader(http.StatusUnauthorized)
//         w.Write(errorBody)
//         return
//     }

//     // Generate JWT including the user ID and role
//     token, err := generateJWT(result.UserID, result.Role)
//     if err != nil {
//         http.Error(w, "failed to generate token", http.StatusInternalServerError)
//         return
//     }

//     response := struct {
//         UserID string `json:"user_id"`
//         Token  string `json:"token"`
//         Role   string `json:"role"` // Include role here
//     }{
//         UserID: result.UserID,
//         Token:  token,
//         Role:   result.Role, // Include role here
//     }

//     fmt.Printf("token is %v\n", token)
//     fmt.Printf("role is %v\n", result.Role)

//     data, _ := json.Marshal(response)
//     w.Write(data)
// }
// func signup(args signupArgs) (response signupOutput, err error) {
//     hashedPassword, err := hashPassword(args.Password)
//     if err != nil {
//         return
//     }

//     variables := map[string]interface{}{
//         "username": args.Username,
//         "email":    args.Email,
//         "password": hashedPassword,
//     }

//     hasuraResponse, err := executeSignup(variables)
//     if err != nil {
//         return
//     }

//     if len(hasuraResponse.Errors) != 0 {
//         err = errors.New(hasuraResponse.Errors[0].Message)
//         return
//     }

//     response = hasuraResponse.Data.Insert_user_one
//     return
// }

// func login(args loginArgs) (response userOutput, err error) {
//     hasuraResponse, err := executeLogin(map[string]interface{}{
//         "email": args.Email,
//     })
//     if err != nil {
//         return
//     }

//     if len(hasuraResponse.Errors) != 0 {
//         err = errors.New(hasuraResponse.Errors[0].Message)
//         return
//     }
//     if len(hasuraResponse.Data.User) == 0 {
//         err = errors.New("invalid credentials")
//         return
//     }

//     user := hasuraResponse.Data.User[0] // Assuming we only need the first match

//     isValid := checkPasswordHash(args.Password, user.Password)
//     if !isValid {
//         err = errors.New("invalid credentials")
//         return
//     }

//     response = user
//     return
// }

// func hashPassword(password string) (string, error) {
//     hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
//     if err != nil {
//         return "", err
//     }
//     return string(hashedPassword), nil
// }

// func checkPasswordHash(password, hash string) bool {
//     err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
//     return err == nil
// }

// // Function to generate JWT token
// func generateJWT(userID, role string) (string, error) {
//     claims := JWTClaims{
//         UserID: userID,
//         Role:   role, // Assign role to the claim
//         StandardClaims: jwt.StandardClaims{
//             ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
//             Issuer:    "cinema_app", // Replace with your app name
//         },
//     }

//     token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//     tokenString, err := token.SignedString(jwtSecret)
//     if err != nil {
//         return "", err
//     }
//     return tokenString, nil
// }
// func executeSignup(variables map[string]interface{}) (response GraphQLResponse, err error) {
//     query := `mutation ($username: String!, $email: String!, $password: String!) {
//         insert_user_one(object: {username: $username, email: $email, password: $password}) {
//             user_id
//         }
//     }`

//     reqBody := GraphQLRequest{
//         Query:     query,
//         Variables: variables,
//     }
//     reqBytes, err := json.Marshal(reqBody)
//     if err != nil {
//         return
//     }

//     resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))
//     if err != nil {
//         return
//     }
//     defer resp.Body.Close()

//     respBytes, err := ioutil.ReadAll(resp.Body)
//     if err != nil {
//         return
//     }

//     if resp.StatusCode != http.StatusOK {
//         err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
//         return
//     }

//     err = json.Unmarshal(respBytes, &response)
//     if err != nil {
//         return
//     }

//     return
// }

// func executeLogin(variables map[string]interface{}) (response GraphQLResponse, err error) {
//     query := `query ($email: String!) {
//         user(where: {email: {_eq: $email}}) {
//             user_id
//             password
//             role
//         }
//     }`

//     reqBody := GraphQLRequest{
//         Query:     query,
//         Variables: variables,
//     }
//     reqBytes, err := json.Marshal(reqBody)
//     if err != nil {
//         return
//     }
//   //here a change in local and internet

//     resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))
//     if err != nil {
//         return
//     }
//     defer resp.Body.Close()

//     respBytes, err := ioutil.ReadAll(resp.Body)
//     if err != nil {
//         return
//     }

//     if resp.StatusCode != http.StatusOK {
//         err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
//         return
//     }

//     err = json.Unmarshal(respBytes, &response)
//     if err != nil {
//         return
//     }

//     return
// }

// func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
//     w.Header().Set("Content-Type", "application/json")

//     // Parse the JSON body
//     var requestBody map[string][]string
//     if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
//         http.Error(w, "Unable to parse JSON body", http.StatusBadRequest)
//         return
//     }

//     // Get the base64 encoded files array from the JSON body
//     base64Files, ok := requestBody["files"]
//     if !ok || len(base64Files) == 0 {
//         http.Error(w, "No file data provided", http.StatusBadRequest)
//         return
//     }

//     // Create a slice to store the URLs of the uploaded images
//     var urls []string

//     // Iterate over the base64 encoded files and upload each one
//     for _, base64File := range base64Files {
//         if base64File == "" {
//             continue
//         }

//         // Decode the base64 string
//         data, err := base64.StdEncoding.DecodeString(base64File)
//         if err != nil {
//             http.Error(w, "Error decoding base64 data", http.StatusBadRequest)
//             return
//         }

//         // Create an io.Reader from the decoded data
//         fileReader := strings.NewReader(string(data))

//         // Upload the file to Cloudinary
//         uploadResponse, err := cloudinaryClient.Upload.Upload(context.Background(), fileReader, uploader.UploadParams{Folder: "assets/img"})
//         if err != nil {
//             http.Error(w, "Error uploading file", http.StatusInternalServerError)
//             return
//         }

//         // Add the secure URL to the list of URLs
//         urls = append(urls, uploadResponse.SecureURL)
//     }

//     // Send the response with the list of URLs
//     response := map[string][]string{
//         "urls": urls,
//     }
//     fmt.Printf("Uploaded files to Cloudinary: %v\n", response)

//     data, err := json.Marshal(response)
//     if err != nil {
//         http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
//         return
//     }

//     w.WriteHeader(http.StatusOK)
//     w.Write(data)
// }

// func sendVerificationEmail(to, username string) error {

//     // Configuration
//     smtpHost := "smtp.gmail.com"
//     smtpPort := "587"
//      smtpUsername := os.Getenv("SMTP_USERNAME")
//     smtpPassword := os.Getenv("SMTP_PASSWORD")
//     // smtpUsername := "mulukendemis44@gmail.com"
//     // smtpPassword := "jnko xwtx rcvd plgq"
//      from := smtpUsername

//      // Print the SMTP credentials (for debugging)
//      fmt.Println("smtpUsername:", smtpUsername)
//      fmt.Println("smtpPassword:", smtpPassword)

//      // Create authentication
//      auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)

//      // Define the email subject and body.
//         subject := "Welcome to MovieVerse, Your Ticket to the Best Cinema Experience!"
//         body := fmt.Sprintf(`
//         Hi %s,

//         Welcome to MovieVerse! 🎟️

//         We are thrilled to have you join our community of cinema lovers. With MovieVerse, you can easily book tickets to the latest movies, find showtimes, and enjoy a seamless movie-going experience.

//         Feel free to explore our platform, check out upcoming releases, and reserve your seat at your favorite cinema.

//         See you at the movies! 🍿

//         Best regards,
//         The MovieVerse Team

//         `, username)

//      message := []byte("Subject: " + subject + "\r\n" +
//         "From: " + from + "\r\n" +
//         "To: " + to + "\r\n" +
//         "\r\n" + body)

//     // Send the email using STARTTLS on port 587.
//     addr := smtpHost + ":" + smtpPort
//     err := smtp.SendMail(addr, auth, from, []string{to}, message)
//     if err != nil {
//         return fmt.Errorf("failed to send email: %v", err)
//     }

//     return nil
// }

// // HTTP handler for the signup event trigger.
// func handleSignupEvent(w http.ResponseWriter, r *http.Request) {
//     var event HasuraEvent
//     // Decode the event payload.
//     if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
//         http.Error(w, "Invalid request payload", http.StatusBadRequest)
//         log.Printf("Error decoding request: %v", err)
//         return
//     }

//       // Extract email, password, role, user_id, and username from the event data.
//     email := event.Event.Data.New.Email

//     username := event.Event.Data.New.Username

//     // Send the verification email.
//     if err := sendVerificationEmail(email, username); err != nil {
//         http.Error(w, "Failed to send email", http.StatusInternalServerError)
//         log.Printf("Error sending email: %v", err)
//         return
//     }

//     w.WriteHeader(http.StatusOK)
//     w.Write([]byte("Verification email sent successfully"))
//     log.Printf("Verification email sent to %s", email)
// }
