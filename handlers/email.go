package handlers
import (
    "crypto/tls"
    "encoding/json"
    "fmt"
     "net/smtp"

      "os"
    "log"
    "net/http"

    
)

// Define the structure for the incoming Hasura event payload.
type HasuraEvent struct {
    Event struct {
        Data struct {
            New struct {
                Email string `json:"email"`
                Username  string `json:"username"`
            } `json:"new"`
        } `json:"data"`
    } `json:"event"`
}



// func sendVerificationEmail(to, username string) error {
    
//     // Configuration
//     smtpHost := "smtp.gmail.com"
//     smtpPort := "465"
//      smtpUsername := os.Getenv("SMTP_USERNAME")
//     smtpPassword := os.Getenv("SMTP_PASSWORD")
   

//     // smtpUsername := "mulukendemis44@gmail.com"
//     // smtpPassword := "jnko xwtx rcvd plgq"
//      from := smtpUsername

   
//      // Create authentication
//      auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
//   // Print the SMTP credentials (for debugging)
//      fmt.Println("smtpUsername:", smtpUsername)
//      fmt.Println("smtpPassword:", smtpPassword)
//      fmt.Println("smtpPort:", smtpPort)
//      fmt.Println("smtpHost:", smtpHost)
//      // Define the email subject and body.
//    subject := "Welcome to MovieVerse, Your Ticket to the Best Cinema Experience!"
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
//      fmt.Println("oooooooooooooooooooooooooooooooooooo")

//     // Send the email using STARTTLS on port 587.
//     addr := smtpHost + ":" + smtpPort
//     // err := smtp.SendMail(addr, auth, from, []string{to}, message)
//      err := smtp.SendMail(addr, auth, from, []string{to}, message)
//      if err != nil {
//     fmt.Printf("Error sending email: %v\n", err)
//     return fmt.Errorf("failed to send email: %v", err)
//     }
//     //  err := smtp.SendMail(addr, auth, from, []string{to}, message)
//     //      fmt.Println("pppppppppppppppppppppppppp")

//     // if err != nil {
//     //     return fmt.Errorf("failed to send emailsss: %v", err)
//     // }

//     return nil
// }


func sendVerificationEmail(to, username string) error {
    // Configuration
    smtpHost := "smtp.gmail.com"
    smtpPort := "465" // Use 465 for SSL
    smtpUsername := os.Getenv("SMTP_USERNAME")
    smtpPassword := os.Getenv("SMTP_PASSWORD")
    from := smtpUsername

    // Print the SMTP credentials (for debugging)
    fmt.Println("smtpUsername:", smtpUsername)
    fmt.Println("smtpPassword:", smtpPassword)

    // Set up TLS configuration
    tlsconfig := &tls.Config{
        InsecureSkipVerify: true,
        ServerName: smtpHost,
    }

    // Connect to the SMTP server
    conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsconfig)
    if err != nil {
        return fmt.Errorf("failed to connect to SMTP server: %v", err)
    }
    defer conn.Close()

    // Create an SMTP client
    client, err := smtp.NewClient(conn, smtpHost)
    if err != nil {
        return fmt.Errorf("failed to create SMTP client: %v", err)
    }

    // Authenticate
    auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
    if err = client.Auth(auth); err != nil {
        return fmt.Errorf("failed to authenticate: %v", err)
    }

    // Define the email subject and body
    subject := "Welcome to MovieVerse, Your Ticket to the Best Cinema Experience!"
    body := fmt.Sprintf(`
    Hi %s,

    Welcome to MovieVerse! 🎟️

    We are thrilled to have you join our community of cinema lovers. With MovieVerse, you can easily book tickets to the latest movies, find showtimes, and enjoy a seamless movie-going experience.

    Feel free to explore our platform, check out upcoming releases, and reserve your seat at your favorite cinema.

    See you at the movies! 🍿

    Best regards,
    The MovieVerse Team
    `, username)

    message := []byte("Subject: " + subject + "\r\n" +
        "From: " + from + "\r\n" +
        "To: " + to + "\r\n" +
        "\r\n" + body)

    // Set the sender and recipient
    if err = client.Mail(from); err != nil {
        return fmt.Errorf("failed to set sender: %v", err)
    }
    if err = client.Rcpt(to); err != nil {
        return fmt.Errorf("failed to set recipient: %v", err)
    }

    // Send the email body
    w, err := client.Data()
    if err != nil {
        return fmt.Errorf("failed to get data writer: %v", err)
    }
    _, err = w.Write(message)
    if err != nil {
        return fmt.Errorf("failed to write message: %v", err)
    }
    err = w.Close()
    if err != nil {
        return fmt.Errorf("failed to close writer: %v", err)
    }

    return nil
}

// HTTP handler for the signup event trigger.
func HandleSignupEvent(w http.ResponseWriter, r *http.Request) {
    var event HasuraEvent
    // Decode the event payload.
    if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        log.Printf("Error decoding request: %v", err)
        return
    }

 
      // Extract email, password, role, user_id, and username from the event data.
    email := event.Event.Data.New.Email

    username := event.Event.Data.New.Username

    // Send the verification email.
    if err := sendVerificationEmail(email, username); err != nil {
        http.Error(w, "Failed to send email kk", http.StatusInternalServerError)
        log.Printf("Error sending email: %v", err)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Verification email sent successfully"))
    log.Printf("Verification email sent to %s", email)
}
