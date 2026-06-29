package warp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// ParseAWGTags parses AWG <tag> format and returns assembled bytes.
// Supports: <b 0xHEX>, <r N>, <rd N>, <rc N>, <t>
func ParseAWGTags(s string) ([]byte, error) {
	var result []byte
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			break
		}
		if !strings.HasPrefix(s, "<") {
			return nil, fmt.Errorf("expected '<', got: %q", s[:min(len(s), 20)])
		}
		closeB := strings.IndexByte(s, '>')
		if closeB < 0 {
			return nil, fmt.Errorf("missing '>' in tag")
		}
		tag := s[1:closeB]
		s = s[closeB+1:]

		parts := strings.Fields(tag)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty tag")
		}

		switch parts[0] {
		case "b":
			if len(parts) < 2 {
				return nil, fmt.Errorf("<b> requires hex arg")
			}
			hexStr := strings.TrimPrefix(parts[1], "0x")
			data, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, fmt.Errorf("<b> invalid hex: %w", err)
			}
			result = append(result, data...)
		case "r":
			if len(parts) < 2 {
				return nil, fmt.Errorf("<r> requires size arg")
			}
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("<r> invalid size: %s", parts[1])
			}
			buf := make([]byte, n)
			rand.Read(buf)
			result = append(result, buf...)
		case "rd":
			if len(parts) < 2 {
				return nil, fmt.Errorf("<rd> requires size arg")
			}
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("<rd> invalid size: %s", parts[1])
			}
			buf := make([]byte, n)
			digits := []byte("0123456789")
			for i := range buf {
				idx, _ := rand.Int(rand.Reader, big.NewInt(10))
				buf[i] = digits[idx.Int64()]
			}
			result = append(result, buf...)
		case "rc":
			if len(parts) < 2 {
				return nil, fmt.Errorf("<rc> requires size arg")
			}
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("<rc> invalid size: %s", parts[1])
			}
			buf := make([]byte, n)
			chars := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			for i := range buf {
				idx, _ := rand.Int(rand.Reader, big.NewInt(52))
				buf[i] = chars[idx.Int64()]
			}
			result = append(result, buf...)
		case "t":
			var ts [4]byte
			binary.LittleEndian.PutUint32(ts[:], uint32(time.Now().Unix()))
			result = append(result, ts[:]...)
		default:
			return nil, fmt.Errorf("unknown AWG tag: %s", parts[0])
		}
	}
	return result, nil
}

// AWGPackets holds junk noise + final payload for a scanner probe.
type AWGPackets struct {
	Junk    [][]byte // warp-plus junk (send with delays)
	Payload []byte   // final payload: plain WG Init + optional padding
}

// BuildJunkPackets constructs warp-plus style junk noise + plain WireGuard initiation.
// This is the correct approach for Cloudflare WARP scanning: random noise
// confuses DPI before the real handshake, without AWG frames (which
// Cloudflare servers don't understand).
func BuildJunkPackets(wgInit []byte, s2Padding int) *AWGPackets {
	p := &AWGPackets{}

	// warp-plus junk (20-50 random packets)
	junkCount := int(20 + randomInt64(0, 30))
	for i := 0; i < junkCount; i++ {
		size := int(40 + randomInt64(0, 60))
		pkt := make([]byte, size)
		rand.Read(pkt)
		p.Junk = append(p.Junk, pkt)
	}

	// Plain WG Init with optional S2 padding
	p.Payload = make([]byte, s2Padding+len(wgInit))
	if s2Padding > 0 {
		rand.Read(p.Payload[:s2Padding])
	}
	copy(p.Payload[s2Padding:], wgInit)

	return p
}

// IsValidWGResponse checks if raw bytes contain a valid WireGuard handshake response.
// A valid response: type=2 (uint32 LE) and length >= 60 bytes.
func IsValidWGResponse(raw []byte) bool {
	if len(raw) < 60 {
		return false
	}
	return binary.LittleEndian.Uint32(raw[:4]) == 2
}

func randomInt64(min, max int64) int64 {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max-min))
	if err != nil {
		return min
	}
	return min + n.Int64()
}
