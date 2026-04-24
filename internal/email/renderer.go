package email

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

// TemplateRenderer renders HTML email templates using Go's html/template.
type TemplateRenderer struct {
	templates map[string]*template.Template
}

// NewTemplateRenderer loads and parses all email templates.
func NewTemplateRenderer() (*TemplateRenderer, error) {
	base, err := templateFS.ReadFile("templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("failed to read base template: %w", err)
	}

	r := &TemplateRenderer{
		templates: make(map[string]*template.Template),
	}

	// Register each content template with the base layout.
	contentTemplates := []string{
		"verification",
		"welcome",
	}

	for _, name := range contentTemplates {
		content, err := templateFS.ReadFile(fmt.Sprintf("templates/%s.html", name))
		if err != nil {
			return nil, fmt.Errorf("failed to read template %s: %w", name, err)
		}

		tmpl, err := template.New("base").Parse(string(base))
		if err != nil {
			return nil, fmt.Errorf("failed to parse base template for %s: %w", name, err)
		}

		tmpl, err = tmpl.Parse(string(content))
		if err != nil {
			return nil, fmt.Errorf("failed to parse content template %s: %w", name, err)
		}

		r.templates[name] = tmpl
	}

	return r, nil
}

// VerificationData holds the data for the verification email template.
type VerificationData struct {
	Subject   string
	Preheader string
	FirstName string
	Code      string
	Year      int
}

// WelcomeData holds the data for the welcome email template.
type WelcomeData struct {
	Subject      string
	Preheader    string
	FirstName    string
	DashboardURL string
	Year         int
}

// RenderVerification renders the verification email HTML.
func (r *TemplateRenderer) RenderVerification(firstName, code string) (string, error) {
	data := VerificationData{
		Subject:   "Aegis — Verify your email",
		Preheader: fmt.Sprintf("Your verification code is %s. It expires in 15 minutes.", code),
		FirstName: firstName,
		Code:      code,
		Year:      time.Now().Year(),
	}

	return r.render("verification", data)
}

// RenderWelcome renders the welcome email HTML.
func (r *TemplateRenderer) RenderWelcome(firstName, dashboardURL string) (string, error) {
	data := WelcomeData{
		Subject:      "Welcome to Aegis",
		Preheader:    fmt.Sprintf("Hi %s, your email is verified. Start managing your secrets.", firstName),
		FirstName:    firstName,
		DashboardURL: dashboardURL,
		Year:         time.Now().Year(),
	}

	return r.render("welcome", data)
}

// render executes a named template and returns the rendered HTML string.
func (r *TemplateRenderer) render(name string, data interface{}) (string, error) {
	tmpl, ok := r.templates[name]
	if !ok {
		return "", fmt.Errorf("template %q not found", name)
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		return "", fmt.Errorf("failed to render template %s: %w", name, err)
	}

	return buf.String(), nil
}
