package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

func jsonMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

type json_RawMessage = json.RawMessage

// randSuffix produces 6 random hex characters for session IDs.
func randSuffix() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "000000"
	}
	return hex.EncodeToString(b)
}
