package warp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// QUIC salt for initial secret derivation (RFC 9001)
var quicSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

func quicVarint(x uint64) []byte {
	if x < 0x40 {
		return []byte{byte(x)}
	} else if x < 0x4000 {
		result := make([]byte, 2)
		binary.BigEndian.PutUint16(result, uint16(x))
		result[0] |= 0x40
		return result
	} else if x < 0x40000000 {
		result := make([]byte, 4)
		binary.BigEndian.PutUint32(result, uint32(x))
		result[0] |= 0x80
		return result
	}
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, x)
	result[0] |= 0xC0
	return result
}

func quicVarintLength(x uint64) int {
	if x < 0x40 {
		return 1
	} else if x < 0x4000 {
		return 2
	} else if x < 0x40000000 {
		return 4
	}
	return 8
}

func quicStr8(data []byte) []byte {
	if data == nil {
		return []byte{0}
	}
	r := make([]byte, 1+len(data))
	r[0] = byte(len(data))
	copy(r[1:], data)
	return r
}

func quicStr16(data []byte) []byte {
	if data == nil {
		return []byte{0, 0}
	}
	r := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(r, uint16(len(data)))
	copy(r[2:], data)
	return r
}

func quicConcat(buffers ...[]byte) []byte {
	n := 0
	for _, b := range buffers {
		n += len(b)
	}
	r := make([]byte, 0, n)
	for _, b := range buffers {
		r = append(r, b...)
	}
	return r
}

func quicXor(dst, src []byte, dstOff, srcOff, length int) {
	for i := 0; i < length; i++ {
		dst[dstOff+i] ^= src[srcOff+i]
	}
}

func quicHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func quicDeriveSecret(key []byte, length int, label string) []byte {
	dataBuffer := quicConcat(
		quicStr8([]byte("tls13 "+label)),
		quicStr8(nil),
		[]byte{0x01},
	)
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(length))
	return quicHMAC(key, append(prefix, dataBuffer...))[:length]
}

func quicEncryptPayload(key, payload, iv, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, iv, payload, aad), nil
}

func quicDeriveHpMask(key, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	result := make([]byte, 16)
	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(result, sample[:16])
	return result, nil
}

func quicTlsExtSni(sni string) []byte {
	hostname := []byte(sni)
	nameEntry := quicConcat([]byte{0x00}, quicStr16(hostname))
	listLen := uint16(len(nameEntry))
	extContent := quicConcat(
		[]byte{byte(listLen >> 8), byte(listLen)},
		nameEntry,
	)
	return quicTlsExt(0x0000, extContent)
}

func quicTlsExt(code uint16, content []byte) []byte {
	r := make([]byte, 4+len(content))
	binary.BigEndian.PutUint16(r, code)
	binary.BigEndian.PutUint16(r[2:], uint16(len(content)))
	copy(r[4:], content)
	return r
}

func quicTlsClientHelloSniOnly(sni string) []byte {
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)

	sniExt := quicTlsExtSni(sni)
	clientHello := quicConcat(
		[]byte{0x03, 0x03},
		randomBytes,
		[]byte{0, 0, 0, 0},
		quicStr16(sniExt),
	)

	// Wrap: [0x01][3-byte length][content]
	r := make([]byte, 4+len(clientHello))
	r[0] = 0x01
	l := len(clientHello)
	r[1] = byte(l >> 16)
	r[2] = byte(l >> 8)
	r[3] = byte(l)
	copy(r[4:], clientHello)
	return r
}

func quicCryptoFrame(data []byte, offset int) []byte {
	return quicConcat(
		[]byte{0x06},
		quicVarint(uint64(offset)),
		quicVarint(uint64(len(data))),
		data,
	)
}

func quicMeasureLengths(dcidLen, scidLen, tokenLen, pknLen, payloadLen int, padto int) (headerLen, paddingLen int) {
	baseHeader := 8 + dcidLen + scidLen + tokenLen + pknLen
	tagLen := 16

	getLenByteSize := func() int { return quicVarintLength(uint64(pknLen + payloadLen + paddingLen + tagLen)) }
	getOverall := func() int { return baseHeader + getLenByteSize() + payloadLen + paddingLen + tagLen }

	overall := getOverall()
	if overall < padto {
		paddingLen = padto - overall
		for paddingLen > 0 && getOverall() > padto {
			paddingLen--
		}
		if getOverall() < padto {
			paddingLen++
		}
		overall = getOverall()
	}
	if pknLen+payloadLen+paddingLen+tagLen < 20 {
		paddingLen = 20 - pknLen - payloadLen - tagLen
		overall = getOverall()
	}
	headerLen = baseHeader + getLenByteSize()
	return
}

func quicInitial(dcid, scid, token, pkn, payload []byte, padto int) ([]byte, error) {
	hdrLen, padLen := quicMeasureLengths(len(dcid), len(scid), len(token), len(pkn), len(payload), padto)

	header := quicConcat(
		[]byte{0xC0 | byte(len(pkn)-1), 0, 0, 0, 1},
		quicStr8(dcid),
		quicStr8(scid),
		quicStr8(token),
		quicVarint(uint64(len(pkn) + len(payload) + padLen + 16)),
		pkn,
	)

	// Derive keys
	initSecret := quicHMAC(quicSalt, dcid)
	clientSecret := quicDeriveSecret(initSecret, 32, "client in")
	quicKey := quicDeriveSecret(clientSecret, 16, "quic key")
	quicIv := quicDeriveSecret(clientSecret, 12, "quic iv")
	quicHp := quicDeriveSecret(clientSecret, 16, "quic hp")

	// XOR IV with PKN
	quicXor(quicIv, pkn, 12-len(pkn), 0, len(pkn))

	// Pad and encrypt
	paddedPayload := make([]byte, len(payload)+padLen)
	copy(paddedPayload, payload)
	encryptedPayload, err := quicEncryptPayload(quicKey, paddedPayload, quicIv, header)
	if err != nil {
		return nil, err
	}

	// Header protection
	sampleOffset := hdrLen - len(pkn) + 4
	if sampleOffset < 0 {
		sampleOffset = 0
	}
	sample := encryptedPayload[sampleOffset:]
	mask, err := quicDeriveHpMask(quicHp, sample)
	if err != nil {
		return nil, err
	}
	mask[0] &= 0x0f
	quicXor(header, mask, 0, 0, 1)
	quicXor(header, mask, len(header)-len(pkn), 1, len(pkn))

	return quicConcat(header, encryptedPayload), nil
}

// GenerateI1FromSNI generates a QUIC Initial packet from a domain name (SNI).
// Returns the I1 value in AmneziaWG format: "<b 0x...>"
func GenerateI1FromSNI(sni string) (string, error) {
	if sni == "" {
		return "", fmt.Errorf("SNI domain cannot be empty")
	}

	dcid := make([]byte, 1)
	rand.Read(dcid)
	scid := []byte{}
	token := []byte{}
	pkn := []byte{0}

	clientHello := quicTlsClientHelloSniOnly(sni)
	payload := quicCryptoFrame(clientHello, 0)

	packet, err := quicInitial(dcid, scid, token, pkn, payload, 0)
	if err != nil {
		return "", fmt.Errorf("generate QUIC Initial: %w", err)
	}

	return "<b 0x" + hex.EncodeToString(packet) + ">", nil
}