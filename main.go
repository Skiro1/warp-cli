package main

import (
	"fmt"
	"os"

	"warp-cli/cmd"
	"warp-cli/tunnel"
)

func main() {
	args := os.Args[1:]

	// Service mode: awarp.exe --service <intf> <profile_path>
	if len(args) >= 2 && args[0] == "--service" {
		intf := args[1]
		profilePath := ""
		if len(args) >= 3 {
			profilePath = args[2]
		}
		if err := tunnel.RunService(intf, profilePath); err != nil {
			fmt.Fprintf(os.Stderr, "Service error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(args) == 0 {
		cmd.Help()
		os.Exit(0)
	}

	command := args[0]
	args = args[1:]

	switch command {
	case "help", "--help", "-h":
		cmd.Help()

	case "register":
		profile, license, awgArgs, sni, _ := parseFlags(args)
		if err := cmd.Register(profile, license, awgArgs, sni); err != nil {
			errExit(err)
		}

	case "up":
		profile, _, _, _, _ := parseFlags(args)
		if err := cmd.Up(profile); err != nil {
			errExit(err)
		}

	case "down":
		profile, _, _, _, _ := parseFlags(args)
		if err := cmd.Down(profile); err != nil {
			errExit(err)
		}

	case "status":
		profile, _, _, _, _ := parseFlags(args)
		if err := cmd.Status(profile); err != nil {
			errExit(err)
		}

	case "config":
		handleConfig(args)

	case "scan":
		if err := cmd.ScanEndpoints(); err != nil {
			errExit(err)
		}

	default:
		cmd.Help()
		os.Exit(1)
	}
}

func handleConfig(args []string) {
	if len(args) == 0 {
		cmd.Help()
		os.Exit(1)
	}

	sub := args[0]
	args = args[1:]

	switch sub {
	case "show":
		profile, _, _, _, _ := parseFlags(args)
		if err := cmd.ConfigShow(profile); err != nil {
			errExit(err)
		}
	case "set":
		profile, _, awgArgs, _, endpoint := parseFlags(args)
		if err := cmd.ConfigSet(profile, awgArgs, endpoint); err != nil {
			errExit(err)
		}
	case "profiles":
		if err := cmd.ConfigProfiles(); err != nil {
			errExit(err)
		}
	case "delete":
		profile, _, _, _, _ := parseFlags(args)
		if err := cmd.ConfigDelete(profile); err != nil {
			errExit(err)
		}
	default:
		cmd.Help()
		os.Exit(1)
	}
}

func parseFlags(args []string) (profile string, license string, awgArgs []string, sni string, endpoint string) {
	profile = "warp"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile", "-p":
			if i+1 < len(args) {
				i++
				profile = args[i]
			}
		case "--license", "-l":
			if i+1 < len(args) {
				i++
				license = args[i]
			}
		case "--set-awg", "-a":
			if i+1 < len(args) {
				i++
				awgArgs = append(awgArgs, args[i])
			}
		case "--sni":
			if i+1 < len(args) {
				i++
				sni = args[i]
			}
		case "--endpoint", "-e":
			if i+1 < len(args) {
				i++
				endpoint = args[i]
			}
		}
	}
	return
}

func errExit(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
