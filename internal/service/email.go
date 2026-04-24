package service

import (
	"fmt"
	"net/smtp"

	"github.com/oluwasemilore/aegis/internal/email"
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
	renderer *email.TemplateRenderer
}

// NewEmailService creates a new email service.
func NewEmailService(host string, port int, user, pass, from string, devMode bool) *EmailService {
	renderer, err := email.NewTemplateRenderer()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise email template renderer")
	}

	return &EmailService{
		host: host, port: port, user: user, pass: pass, from: from,
		devMode: devMode, renderer: renderer,
	}
}

// SendVerification sends a verification code to the user's email.
func (s *EmailService) SendVerification(to, firstName, code string) error {
	subject := "Aegis — Verify your email"

	htmlBody, err := s.renderer.RenderVerification(firstName, code)
	if err != nil {
		return fmt.Errorf("failed to render verification email: %w", err)
	}

	if s.devMode {
		log.Info().
			Str("to", to).
			Str("code", code).
			Str("first_name", firstName).
			Msg("📧 [DEV] verification email (not sent)")
		return nil
	}

	return s.sendHTML(to, subject, htmlBody)
}

// SendWelcome sends a welcome email after successful verification.
func (s *EmailService) SendWelcome(to, firstName, dashboardURL string) error {
	subject := "Welcome to Aegis"

	htmlBody, err := s.renderer.RenderWelcome(firstName, dashboardURL)
	if err != nil {
		return fmt.Errorf("failed to render welcome email: %w", err)
	}

	if s.devMode {
		log.Info().
			Str("to", to).
			Str("first_name", firstName).
			Msg("📧 [DEV] welcome email (not sent)")
		return nil
	}

	return s.sendHTML(to, subject, htmlBody)
}

// sendHTML sends an HTML email via SMTP.
func (s *EmailService) sendHTML(to, subject, htmlBody string) error {
	headers := fmt.Sprintf(
		"From: Aegis <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		s.from, to, subject,
	)

	msg := headers + htmlBody

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	if err := smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("failed to send email to %s: %w", to, err)
	}

	log.Info().Str("to", to).Str("subject", subject).Msg("email sent")
	return nil
}
