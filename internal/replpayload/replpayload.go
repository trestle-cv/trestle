// Package replpayload defines the consensus-owned automation definition
// payloads shared between the HTTP handlers (which build them, including the
// canonical webhook secret ciphertext) and the replicated FSM (which
// materializes them verbatim). Keeping them in a neutral package avoids an
// import cycle between the product handlers and the replication runtime.
package replpayload

// WebhookPayload is a consensus-owned webhook definition. SecretCipher is the
// canonical AES-GCM ciphertext produced once before proposal and applied
// verbatim by every replica; the FSM never encrypts.
type WebhookPayload struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	Topics       string `json:"topics"`
	SecretCipher []byte `json:"secret_cipher"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// FunctionPayload is a consensus-owned function (Lambda) definition. AWS
// credentials are never part of it; they remain process-local on every node.
type FunctionPayload struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	Target         string `json:"target"`
	Region         string `json:"region"`
	Topics         string `json:"topics"`
	CallbackScopes string `json:"callback_scopes"`
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}
