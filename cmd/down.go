package cmd

import (
	"fmt"
	"warp-cli/config"
	"warp-cli/tunnel"
)

func Down(profileName string) error {
	_, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("profile %q not found", profileName)
	}

	intf := "warp0"
	fmt.Printf("Stopping tunnel service (intf: %s)...\n", intf)

	if err := tunnel.StopAndRemoveService(intf); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}

	fmt.Println("Tunnel service stopped")
	return nil
}
