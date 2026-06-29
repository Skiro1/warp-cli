package warp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
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
	crand.Read(randomBytes)

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

// I1Strategy defines how the QUIC Initial (I1) packet is constructed.
type I1Strategy int

const (
	I1Legacy      I1Strategy = 0 // single CRYPTO frame, no cut
	I1Reorder     I1Strategy = 1 // split and reorder CRYPTO frames
	I1Safe        I1Strategy = 4 // split+skipZeroes, most compatible (default)
)

func (s I1Strategy) String() string {
	switch s {
	case I1Legacy:
		return "legacy"
	case I1Reorder:
		return "reorder"
	case I1Safe:
		return "safe"
	default:
		return "safe"
	}
}

// ParseI1Strategy parses a string into an I1Strategy.
// Valid values: "legacy", "reorder", "safe" (default).
func ParseI1Strategy(s string) I1Strategy {
	switch s {
	case "legacy":
		return I1Legacy
	case "reorder":
		return I1Reorder
	case "safe":
		return I1Safe
	default:
		return I1Safe
	}
}

// Static I1 masks (pre-computed valid QUIC Initial packets).
// Used as fallback when no SNI is provided or as non-SNI alternative.
var I1Masks = []string{
	"<b 0xc10000000114367096bb0fb3f58f3a3fb8aaacd61d63a1c8a40e14f7374b8a62dccba6431716c3abf6f5afbcfb39bd008000047c32e268567c652e6f4db58bff759bc8c5aaca183b87cb4d22938fe7d8dca22a679a79e4d9ee62e4bbb3a380dd78d4e8e48f26b38a1d42d76b371a5a9a0444827a69d1ab5872a85749f65a4104e931740b4dc1e2dd77733fc7fac4f93011cd622f2bb47e85f71992e2d585f8dc765a7a12ddeb879746a267393ad023d267c4bd79f258703e27345155268bd3cc0506ebd72e2e3c6b5b0f005299cd94b67ddabe30389c4f9b5c2d512dcc298c14f14e9b7f931e1dc397926c31fbb7cebfc668349c218672501031ecce151d4cb03c4c660b6c6fe7754e75446cd7de09a8c81030c5f6fb377203f551864f3d83e27de7b86499736cbbb549b2f37f436db1cae0a4ea39930f0534aacdd1e3534bc87877e2afabe959ced261f228d6362e6fd277c88c312d966c8b9f67e4a92e757773db0b0862fb8108d1d8fa262a40a1b4171961f0704c8ba314da2482ac8ed9bd28d4b50f7432d89fd800c25a50c5e2f5c0710544fef5273401116aa0572366d8e49ad758fcb29e6a92912e644dbe227c247cb3417eabfab2db16796b2fba420de3b1dc94e8361f1f324a331ddaf1e626553138860757fd0bf687566108b77b70fb9f8f8962eca599c4a70ed373666961a8cb506b96756d9e28b94122b20f16b54f118c0e603ce0b831efea614ad836df6cf9affbdd09596412547496967da758cec9080295d853b0861670b71d9abde0d562b1a6de82782a5b0c14d297f27283a895abc889a5f6703f0e6eb95f67b2da45f150d0d8ab805612d570c2d5cb6997ac3a7756226c2f5c8982ffbd480c5004b0660a3c9468945efde90864019a2b519458724b55d766e16b0da25c0557c01f3c11ddeb024b62e303640e17fdd57dedb3aeb4a2c1b7c93059f9c1d7118d77caac1cd0f6556e46cbc991c1bb16970273dea833d01e5090d061a0c6d25af2415cd2878af97f6d0e7f1f936247b394ecb9bd484da6be936dee9b0b92dc90101a1b4295e97a9772f2263eb09431995aa173df4ca2abd687d87706f0f93eaa5e13cbe3b574fa3cfe94502ace25265778da6960d561381769c24e0cbd7aac73c16f95ae74ff7ec38124f7c722b9cb151d4b6841343f29be8f35145e1b27021056820fed77003df8554b4155716c8cf6049ef5e318481460a8ce3be7c7bfac695255be84dc491c19e9dedc449dd3471728cd2a3ee51324ccb3eef121e3e08f8e18f0006ea8957371d9f2f739f0b89e4db11e5c6430ada61572e589519fbad4498b460ce6e4407fc2d8f2dd4293a50a0cb8fcaaf35cd9a8cc097e3603fbfa08d9036f52b3e7fcce11b83ad28a4ac12dba0395a0cc871cefd1a2856fffb3f28d82ce35cf80579974778bab13d9b3578d8c75a2d196087a2cd439aff2bb33f2db24ac175fff4ed91d36a4cdbfaf3f83074f03894ea40f17034629890da3efdbb41141b38368ab532209b69f057ddc559c19bc8ae62bf3fd564c9a35d9a83d14a95834a92bae6d9a29ae5e8ece07910d16433e4c6230c9bd7d68b47de0de9843988af6dc88b5301820443bd4d0537778bf6b4c1dd067fcf14b81015f2a67c7f2a28f9cb7e0684d3cb4b1c24d9b343122a086611b489532f1c3a26779da1706c6759d96d8ab>",
	"<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>",
}

// PickI1Mask returns a random static I1 mask.
func PickI1Mask() string {
	return I1Masks[rand.Intn(len(I1Masks))]
}

// quicTlsClientHelloToFrames splits a ClientHello into one or two CRYPTO frames
// depending on cut level. Returns the combined payload and a cutSettings hint.
func quicTlsClientHelloToFrames(clientHello []byte, level I1Strategy) ([]byte, []int) {
	if level == I1Legacy {
		return quicCryptoFrame(clientHello, 0), nil
	}

	// cut presets: [p1s, p1e, p2s, p2e, dropTail, skipZeroes]
	type preset struct{ p1s, p1e, p2s, p2e, dropTail int; skipZeroes bool }
	presets := map[I1Strategy]preset{
		I1Reorder: {38, 1 << 30, 0, 38, 32, false},
		I1Safe:    {0, 1, 38, 1 << 30, 0, true},
	}

	p, ok := presets[level]
	if !ok {
		// fallback to legacy
		return quicCryptoFrame(clientHello, 0), nil
	}

	// Copy the ClientHello into a fixed-size slice for slicing
	ch := make([]byte, len(clientHello))
	copy(ch, clientHello)

	p1End := p.p1e
	if p1End > len(ch) {
		p1End = len(ch)
	}
	p2End := p.p2e
	if p2End > len(ch) {
		p2End = len(ch)
	}

	part1 := ch[p.p1s:p1End]
	part2Start := p.p2s
	if p.skipZeroes {
		for part2Start < len(ch) && ch[part2Start] == 0 {
			part2Start++
		}
	}
	part2 := ch[part2Start:p2End]

	frame1 := quicCryptoFrame(part1, p.p1s)
	frame2 := quicCryptoFrame(part2, part2Start)

	payload := make([]byte, 0, len(frame1)+len(frame2))
	payload = append(payload, frame1...)
	payload = append(payload, frame2...)

	dropTail := p.dropTail
	payload = payload[:len(payload)-dropTail]

	return payload, nil
}

// GenerateI1FromSNI generates a QUIC Initial packet from a domain name (SNI)
// using the specified strategy. Returns the I1 in AmneziaWG format: "<b 0x...>"
func GenerateI1FromSNI(sni string, strategy I1Strategy) (string, error) {
	if sni == "" {
		return "", fmt.Errorf("SNI domain cannot be empty")
	}

	dcid := make([]byte, 1)
	crand.Read(dcid)
	scid := []byte{}
	token := []byte{}
	pkn := []byte{0}

	clientHello := quicTlsClientHelloSniOnly(sni)
	payload, _ := quicTlsClientHelloToFrames(clientHello, strategy)

	packet, err := quicInitial(dcid, scid, token, pkn, payload, 0)
	if err != nil {
		return "", fmt.Errorf("generate QUIC Initial: %w", err)
	}

	return "<b 0x" + hex.EncodeToString(packet) + ">", nil
}