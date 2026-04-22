package pagination

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"time"
)

// Params holds parsed pagination parameters.
type Params struct {
	Limit  int
	Cursor *time.Time
}

// Parse extracts pagination params from query string.
func Parse(r *http.Request) Params {
	p := Params{Limit: 20}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			p.Limit = parsed
		}
	}

	if c := r.URL.Query().Get("cursor"); c != "" {
		decoded, err := base64.URLEncoding.DecodeString(c)
		if err == nil {
			t, err := time.Parse(time.RFC3339Nano, string(decoded))
			if err == nil {
				p.Cursor = &t
			}
		}
	}

	return p
}

// EncodeCursor encodes a timestamp as a cursor string.
func EncodeCursor(t time.Time) string {
	return base64.URLEncoding.EncodeToString([]byte(t.Format(time.RFC3339Nano)))
}
