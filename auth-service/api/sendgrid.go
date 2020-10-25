package api

import (
	"bytes"
	"html/template"
	"os"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

var (
	sendgridKey    string
	sendgridClient *sendgrid.Client
	defaultSender  = mail.NewEmail("CloudComputing Decal", "noreply@calcloud.org")
	defaultScheme  = "http"
)

//InitMailer initalizes the sendgrid client
func InitMailer() {
	// load environmental variables
	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)
}

//SendEmail sends an email to the recipient with the specified subject
func SendEmail(recipient string, subject string, templatePath string, data map[string]interface{}) error {
	// Parse template file and execute with data.
	var html bytes.Buffer
	tmpl, err := template.ParseFiles("./api/templates/" + templatePath)
	if err != nil {
		return err
	}
	err = tmpl.Execute(&html, data)
	if err != nil {
		return err
	}

	//turn our html page buffer into a string
	plainTextContent := html.String()

	recipientEmail := mail.NewEmail("recipient", recipient)

	// Construct and send email via Sendgrid.
	message := mail.NewSingleEmail(defaultSender, subject, recipientEmail, plainTextContent, html.String())

	_, err = sendgridClient.Send(message)
	if err != nil {
		return err
	}

	return nil
}