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

	"warp-cli/config"
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

// AWGPackets holds the complete AWG packet sequence for a scanner probe.
type AWGPackets struct {
	Junk     [][]byte // warp-plus junk (send with delays)
	Sequence [][]byte // AWG sequence (I1, Jc junk, I2-I5, WG Init)
}

// BuildAWGPackets constructs the AWG-wrapped initiation packet sequence.
// Sequence:
//
//	Junk: [random×20-50]   ← warp-plus style, send with 80-150ms delays
//	Seq:  [S1][I1][Jc×random][I2][I3][I4][I5][S2+WG Init]
func BuildAWGPackets(wgInit []byte, awg config.AWGConfig) (*AWGPackets, error) {
	p := &AWGPackets{}

	// warp-plus junk (20-50 random packets)
	junkCount := int(20 + randomInt64(0, 30))
	for i := 0; i < junkCount; i++ {
		size := int(40 + randomInt64(0, 60))
		pkt := make([]byte, size)
		rand.Read(pkt)
		p.Junk = append(p.Junk, pkt)
	}

	// S1 padding
	if awg.S1 > 0 {
		pkt := make([]byte, awg.S1)
		rand.Read(pkt)
		p.Sequence = append(p.Sequence, pkt)
	}

	// I1
	if awg.I1 != "" {
		i1, err := ParseAWGTags(awg.I1)
		if err != nil {
			return nil, fmt.Errorf("parse I1: %w", err)
		}
		p.Sequence = append(p.Sequence, i1)
	}

	// Jc junk frames
	if awg.Jc > 0 {
		for i := 0; i < awg.Jc; i++ {
			size := awg.Jmin
			if awg.Jmax > awg.Jmin {
				size += int(randomInt64(0, int64(awg.Jmax-awg.Jmin)))
			}
			if size < 1 {
				size = 1
			}
			pkt := make([]byte, size)
			rand.Read(pkt)
			p.Sequence = append(p.Sequence, pkt)
		}
	}

	// I2-I5
	for _, tag := range []string{awg.I2, awg.I3, awg.I4, awg.I5} {
		if tag != "" {
			frame, err := ParseAWGTags(tag)
			if err != nil {
				return nil, fmt.Errorf("parse frame: %w", err)
			}
			p.Sequence = append(p.Sequence, frame)
		}
	}

	// S2 padding + WG Init in one packet
	last := make([]byte, awg.S2+len(wgInit))
	if awg.S2 > 0 {
		rand.Read(last[:awg.S2])
	}
	copy(last[awg.S2:], wgInit)
	p.Sequence = append(p.Sequence, last)

	return p, nil
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
