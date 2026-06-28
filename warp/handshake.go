package warp

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
)

func hmacBlake2s(key, data []byte) []byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func kdf1(t0 *[32]byte, key, input []byte) {
	prk := hmacBlake2s(key, input)
	copy(t0[:], hmacBlake2s(prk, []byte{0x1}))
}

func kdf2(t0, t1 *[32]byte, key, input []byte) {
	prk := hmacBlake2s(key, input)
	t0v := hmacBlake2s(prk, []byte{0x1})
	copy(t0[:], t0v)
	copy(t1[:], hmacBlake2s(prk, append(t0v, 0x2)))
}

func mixHash(h *[32]byte, data []byte) {
	hsh, _ := blake2s.New256(nil)
	hsh.Write(h[:])
	hsh.Write(data)
	hsh.Sum(h[:0])
}

func mixKey(c *[32]byte, data []byte) {
	kdf1(c, c[:], data)
}

func tai64nNow() [12]byte {
	var ts [12]byte
	now := time.Now()
	secs := uint64(0x400000000000000a) + uint64(now.Unix())
	nano := uint32(now.Nanosecond()) &^ 0xFFFFFF
	binary.BigEndian.PutUint64(ts[:], secs)
	binary.BigEndian.PutUint32(ts[8:], nano)
	return ts
}

// BuildInitiation builds a valid Noise-IK WireGuard handshake initiation
// using a registered client keypair and the server's public key.
// Returns the 148-byte initiation packet.
func BuildInitiation(clientPrivB64, serverPubB64 string) ([]byte, error) {
	clientPriv, err := base64.StdEncoding.DecodeString(clientPrivB64)
	if err != nil || len(clientPriv) != 32 {
		clientPriv = make([]byte, 32)
		rand.Read(clientPriv)
	}
	serverPub, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil || len(serverPub) != 32 {
		return nil, err
	}

	var clientPub [32]byte
	privArr := (*[32]byte)(clientPriv)
	curve25519.ScalarBaseMult(&clientPub, privArr)

	ephPriv := make([]byte, 32)
	rand.Read(ephPriv)
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	var ephPub [32]byte
	ephArr := (*[32]byte)(ephPriv)
	curve25519.ScalarBaseMult(&ephPub, ephArr)

	chainKey := blake2s.Sum256([]byte(NoiseConstruction))
	hinit, _ := blake2s.New256(nil)
	hinit.Write(chainKey[:])
	hinit.Write([]byte(WGIdentifier))
	var hash [32]byte
	hinit.Sum(hash[:0])

	mixHash(&hash, serverPub)

	msg := make([]byte, 148)
	binary.LittleEndian.PutUint32(msg[0:4], 1)
	var senderIdx [4]byte
	rand.Read(senderIdx[:])
	binary.LittleEndian.PutUint32(msg[4:8], binary.LittleEndian.Uint32(senderIdx[:]))
	copy(msg[8:40], ephPub[:])

	mixKey(&chainKey, ephPub[:])
	mixHash(&hash, ephPub[:])

	var ss [32]byte
	curve25519.ScalarMult(&ss, ephArr, (*[32]byte)(serverPub))

	var key [32]byte
	kdf2(&chainKey, &key, chainKey[:], ss[:])

	var zeroNonce [12]byte
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg[40:40], zeroNonce[:], clientPub[:], hash[:])

	mixHash(&hash, msg[40:88])

	var ss2 [32]byte
	curve25519.ScalarMult(&ss2, privArr, (*[32]byte)(serverPub))

	kdf2(&chainKey, &key, chainKey[:], ss2[:])

	timestamp := tai64nNow()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg[88:88], zeroNonce[:], timestamp[:], hash[:])

	mixHash(&hash, msg[88:116])

	ComputeMAC1(msg, serverPub)

	return msg, nil
}

// ComputeMAC1 computes MAC1 for a WG initiation message using the server's public key.
func ComputeMAC1(msg, serverPub []byte) {
	h, _ := blake2s.New256(nil)
	h.Write([]byte(WGLabelMAC1))
	h.Write(serverPub)
	mac1Key := h.Sum(nil)

	mac, _ := blake2s.New128(mac1Key)
	mac.Write(msg[:116])
	mac.Sum(msg[:116])
}
