// Package resend sends email via the Resend HTTP API.
package resend

import (
	"context"
	"fmt"

	"github.com/dayaneroot/auth-service/internal/domain"
	resendapi "github.com/resend/resend-go/v3"
)

// Mailer delivers email through Resend's HTTP API (no local shell).
type Mailer struct {
	client *resendapi.Client
	from   string
}

// NewMailer builds a Resend client; apiKey and from come from config/env only.
func NewMailer(apiKey, from string) *Mailer {
	return &Mailer{client: resendapi.NewClient(apiKey), from: from}
}

func (m *Mailer) Send(ctx context.Context, msg domain.EmailMessage) error {
	if msg.To == "" || msg.Subject == "" {
		return fmt.Errorf("resend: missing to or subject")
	}
	_, err := m.client.Emails.SendWithContext(ctx, &resendapi.SendEmailRequest{
		From:    m.from,
		To:      []string{msg.To},
		Subject: msg.Subject,
		Text:    msg.Text,
		Html:    msg.HTML,
	})
	if err != nil {
		return fmt.Errorf("resend send: %w", err)
	}
	return nil
}
