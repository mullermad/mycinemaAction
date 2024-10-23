package handlers
// https://mycinemaaction.onrender.com/signup
import (
    "encoding/json"
    "fmt"
	"context"
	"encoding/base64"
    "strings"
      "os"
    "log"
    "net/http"
    "github.com/joho/godotenv"
    "github.com/cloudinary/cloudinary-go/v2"
    "github.com/cloudinary/cloudinary-go/v2/api/uploader"
    
)

var cloudinaryClient *cloudinary.Cloudinary

func init() {
// Load environment variables from the .env file
// var err error
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

     //Get Cloudinary credentials from environment variables
     cloudName:= os.Getenv("CLOUDINARY_CLOUD_NAME")
    apiKey:= os.Getenv("CLOUDINARY_API_KEY")
    apiSecret:= os.Getenv("CLOUDINARY_API_SECRET")
     if cloudName == "" || apiKey == "" || apiSecret == "" {
        log.Fatal("Cloudinary environment variables are not set")
    }
    // fmt.Printf("cloudName %v apiKey %v apiSecret %v ",cloudName,apiKey,apiSecret)
   

  cloudinaryClient, err = cloudinary.NewFromParams(cloudName, apiKey, apiSecret)
   
        if err != nil {
        log.Fatalf("Error initializing Cloudinary client: %v", err)
    }
}

func UploadFileHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Parse the JSON body
    var requestBody map[string][]string
    if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
        http.Error(w, "Unable to parse JSON body", http.StatusBadRequest)
        return
    }

    // Get the base64 encoded files array from the JSON body
    base64Files, ok := requestBody["files"]
    if !ok || len(base64Files) == 0 {
        http.Error(w, "No file data provided", http.StatusBadRequest)
        return
    }

    // Create a slice to store the URLs of the uploaded images
    var urls []string

    // Iterate over the base64 encoded files and upload each one
    for _, base64File := range base64Files {
        if base64File == "" {
            continue
        }

        // Decode the base64 string
        data, err := base64.StdEncoding.DecodeString(base64File)
        if err != nil {
            http.Error(w, "Error decoding base64 data", http.StatusBadRequest)
            return
        }

        // Create an io.Reader from the decoded data
        fileReader := strings.NewReader(string(data))

        // Upload the file to Cloudinary
        uploadResponse, err := cloudinaryClient.Upload.Upload(context.Background(), fileReader, uploader.UploadParams{Folder: "assets/img"})
        if err != nil {
            http.Error(w, "Error uploading file", http.StatusInternalServerError)
            return
        }

        // Add the secure URL to the list of URLs
        urls = append(urls, uploadResponse.SecureURL)
    }

    // Send the response with the list of URLs
    response := map[string][]string{
        "urls": urls,
    }
    fmt.Printf("Uploaded files to Cloudinary: %v\n", response)

    data, err := json.Marshal(response)
    if err != nil {
        http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write(data)
}
