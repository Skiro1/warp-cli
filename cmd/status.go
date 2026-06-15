package cmd

import (
	"fmt"
	"warp-cli/config"
	"warp-cli/tunnel"
)

func Status(profileName string) error {
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("profile %q not found: %w", profileName, err)
	}

	fmt.Printf("Profile:  %s\n", profile.Name)
	fmt.Printf("Address:  %s\n", profile.Address)
	fmt.Printf("DNS:      %s\n", profile.DNS)
	fmt.Printf("Endpoint: %s\n", profile.Endpoint)
	fmt.Printf("AWG:      jc=%d jmin=%d jmax=%d s1=%d s2=%d\n",
		profile.AWG.Jc, profile.AWG.Jmin, profile.AWG.Jmax,
		profile.AWG.S1, profile.AWG.S2)
	fmt.Println()

	if err := tunnel.Status(profile); err != nil {
		fmt.Printf("Tunnel status: %v\n", err)
	}

	return nil
}
