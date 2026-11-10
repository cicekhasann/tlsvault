package record

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidRecord = errors.New("tlsvault: invalid tls record header")
	ErrFrameTooLarge = errors.New("tlsvault: record length exceeds max TLS frame (16384 bytes)")
)

type ContentType uint8

const (
	TypeChangeCipherSpec ContentType = 20
	TypeAlert            ContentType = 21
	TypeHandshake        ContentType = 22
	TypeApplicationData  ContentType = 23
	TypeHeartbeat        ContentType = 24
)

func (c ContentType) String() string {
	switch c {
	case TypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case TypeAlert:
		return "Alert"
	case TypeHandshake:
		return "Handshake"
	case TypeApplicationData:
		return "ApplicationData"
	case TypeHeartbeat:
		return "Heartbeat"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", uint8(c))
	}
}

type Header struct {
	Type    ContentType
	Version uint16
	Length  uint16
}

// ParseHeader decodes the 5-byte TLS record layer header.
func ParseHeader(r io.Reader) (Header, error) {
	var buf [5]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Header{}, err
	}

	h := Header{
		Type:    ContentType(buf[0]),
		Version: binary.BigEndian.Uint16(buf[1:3]),
		Length:  binary.BigEndian.Uint16(buf[3:5]),
	}

	if h.Length > 16384+2048 { // RFC 8446 max record length with padding
		return h, ErrFrameTooLarge
	}

	return h, nil
}
