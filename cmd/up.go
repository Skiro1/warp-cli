package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"warp-cli/config"
	"warp-cli/tunnel"
	"warp-cli/warp"
)

func Up(profileName string) error {
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("load profile %q: %w\nRun 'warp-cli register --profile %s' first", profileName, err, profileName)
	}

	wc := warp.NewClient()
	token := profile.Token
	accID := profile.AccountID
	if accID == "" {
		accID = profile.ClientID
	}
	if token != "" {
		if err := wc.KeepAlive(token, accID); err != nil {
			fmt.Printf("WARP keepalive: %v\n", err)
		} else {
			fmt.Println("WARP keepalive: OK")
		}
	}

	stopKeepalive := make(chan struct{})
	if token != "" {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := wc.KeepAlive(token, accID); err != nil {
						fmt.Printf("WARP keepalive: %v\n", err)
					}
				case <-stopKeepalive:
					return
				}
			}
		}()
	}

	intf := "warp0"
	fmt.Printf("Starting tunnel service (intf: %s, profile: %s)...\n", intf, profileName)

	if err := tunnel.InstallAndStartService(intf, profile); err != nil {
		close(stopKeepalive)
		return fmt.Errorf("start service: %w", err)
	}

	fmt.Println("Tunnel service started successfully")
	fmt.Println("Press Ctrl+C to stop")

	// Wait for Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh

	fmt.Println("\nStopping service...")
	if err := tunnel.StopAndRemoveService(intf); err != nil {
		fmt.Printf("Warning: stop service: %v\n", err)
	}

	close(stopKeepalive)
	fmt.Println("Tunnel stopped.")
	os.Exit(0)
	return nil
}
