package cmd

import (
	"fmt"
	"strings"

	"warp-cli/config"
	"warp-cli/tunnel"
	"warp-cli/warp"
)

func Register(profileName, license string, awgArgs []string, sni string) error {
	existing, _ := config.LoadProfile(profileName)
	if existing != nil && existing.PrivateKey != "" {
		return fmt.Errorf("profile %q already exists. Use a different name or delete it first", profileName)
	}

	wc := warp.NewClient()

	privKey, pubKey, err := warp.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}

	req := &warp.RegisterRequest{
		Key:         pubKey,
		InstallID:   "",
		FCMToken:    "",
		Referer:     "",
		WarpEnabled: true,
		Locale:      "en-US",
	}
	if license != "" {
		req.License = license
	}

	resp, err := wc.Register(req)
	if err != nil {
		return fmt.Errorf("register with WARP: %w", err)
	}

	endpoint := config.DefaultEndpoint
	if len(resp.Config.Peers) == 0 {
		return fmt.Errorf("no peers in WARP response")
	}

	peer := resp.Config.Peers[0]
	serverKey := peer.PublicKey
	port := 2408
	if peer.Endpoint.Host != "" {
		endpoint = peer.Endpoint.Host
		if !strings.Contains(endpoint, ":") {
			endpoint = fmt.Sprintf("%s:%d", endpoint, port)
		}
	} else if peer.Endpoint.V4 != "" {
		endpoint = fmt.Sprintf("%s:%d", peer.Endpoint.V4, port)
	}

	awg := config.DefaultAWG
	if len(awgArgs) > 0 {
		parsed, err := tunnel.ParseAWGArgs(awgArgs)
		if err != nil {
			return fmt.Errorf("parse awg args: %w", err)
		}
		awg = parsed
	}

	if sni != "" {
		i1, err := warp.GenerateI1FromSNI(sni)
		if err != nil {
			return fmt.Errorf("generate I1 from SNI %q: %w", sni, err)
		}
		awg.I1 = i1
		fmt.Printf("  I1 (SNI: %s): generated\n", sni)
	}

	profile := &config.Profile{
		Name:       profileName,
		PrivateKey: privKey,
		Address:    resp.Config.Interface.Addresses.V4,
		Address6:   resp.Config.Interface.Addresses.V6,
		DNS:        config.DefaultDNS,
		PublicKey:  serverKey,
		Endpoint:   endpoint,
		AccountID:  resp.ID,
		ClientID:   resp.Config.ClientID,
		Token:      resp.Token,
		License:    license,
		AWG:        awg,
	}

	if err := profile.Save(); err != nil {
		return fmt.Errorf("save profile: %w", err)
	}

	fmt.Printf("Profile %q created.\n", profileName)
	fmt.Printf("  Private key: %s\n", maskKey(privKey))
	fmt.Printf("  Address:     %s\n", profile.Address)
	if profile.Address6 != "" {
		fmt.Printf("  Address6:    %s\n", profile.Address6)
	}
	fmt.Printf("  DNS:         %s\n", config.DefaultDNS)
	fmt.Printf("  Endpoint:    %s\n", endpoint)
	if license != "" {
		fmt.Printf("  WARP+:       yes (license)\n")
	}
	fmt.Println()
	fmt.Println("Run: awarp up --profile", profileName)

	return nil
}

func maskKey(k string) string {
	if len(k) < 20 {
		return k
	}
	return k[:8] + "..." + k[len(k)-8:]
}
