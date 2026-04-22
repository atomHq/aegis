package service

import (
	"fmt"
	"net/smtp"

	"github.com/rs/zerolog/log"
)

// EmailService handles sending emails.
type EmailService struct {
	host     string
	port     int
	user     string
	pass     string
	from     string
	devMode  bool // In dev mode, log codes to console instead of sending
}

// NewEmailService creates a new email service.
func NewEmailService(host string, port int, user, pass, from string, devMode bool) *EmailService {
	return &EmailService{
		host: host, port: port, user: user, pass: pass, from: from, devMode: devMode,
	}
}

// SendVerification sends a verification code to the user's email.
func (s *EmailService) SendVerification(to, firstName, code string) error {
	subject := "Aegis — Verify your email"
	body := fmt.Sprintf(
		"Hi %s,\n\nYour verification code is: %s\n\nThis code expires in 15 minutes.\n\nIf you didn't create an Aegis account, please ignore this email.\n\n— Aegis Team",
		firstName, code,
	)

	if s.devMode {
		log.Info().
			Str("to", to).
			Str("code", code).
			Str("first_name", firstName).
			Msg("📧 [DEV] verification email (not sent)")
		return nil
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		s.from, to, subject, body,
	)

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	if err := smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("failed to send email to %s: %w", to, err)
	}

	log.Info().Str("to", to).Msg("verification email sent")
	return nil
}
