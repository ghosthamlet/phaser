package async

import (
	"encoding/json"
)

// Message is used to send and receive messages between services
type Message struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// DecodedMessage is a unmarshaled Message
type DecodedMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}
