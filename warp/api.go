package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
)

const (
	apiBaseURL = "https://api.cloudflareclient.com"
	apiVersion = "v0a2158"
	userAgent  = "okhttp/3.12.1"
	timeout    = 20 * time.Second
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
	}
}

// NewClientWithUTLS creates a client with uTLS fingerprint rotation (stdlib + uTLS fallback).
// Useful in regions with TLS fingerprint blocking.
func NewClientWithUTLS() *Client {
	tr := &http.Transport{
		DialTLSContext: dialUTLSWithFallback,
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout, Transport: tr},
	}
}

// dialUTLSWithFallback tries stdlib TLS first, then uTLS Chrome/Firefox fingerprints.
func dialUTLSWithFallback(ctx context.Context, network, addr string) (net.Conn, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	// Tier 1: stdlib TLS
	tcpConn, err := new(net.Dialer).DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err == nil {
		return tlsConn, nil
	}
	tcpConn.Close()

	// Tier 2: uTLS Chrome fingerprint
	specs := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
	}
	for _, spec := range specs {
		tcpConn, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			continue
		}
		uConn := utls.UClient(tcpConn, &utls.Config{
			ServerName: "api.cloudflareclient.com",
			NextProtos: []string{"h2", "http/1.1"},
		}, spec)
		if err := uConn.Handshake(); err == nil {
			return uConn, nil
		}
		tcpConn.Close()
	}

	return nil, fmt.Errorf("all TLS methods failed")
}

func GenerateKeyPair() (privateKey, publicKey string, err error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	privateKey = base64.StdEncoding.EncodeToString(sk[:])
	publicKey = base64.StdEncoding.EncodeToString(pk[:])
	return privateKey, publicKey, nil
}

func (c *Client) Register(req *RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", apiBaseURL+"/"+apiVersion+"/reg", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w, body: %s", err, string(respBody))
	}

	return &result, nil
}

func (c *Client) KeepAlive(token, accountID string) error {
	path := "/" + apiVersion + "/reg/" + accountID
	body := `{"warp_enabled":true}`

	req, err := http.NewRequest("PATCH", apiBaseURL+path, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create keepalive request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keepalive request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keepalive API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
