//go:build windows

package tunnel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"warp-cli/config"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceDataDir = `C:\ProgramData\Awarp`

func serviceConfigFile(intf string) string {
	return filepath.Join(serviceDataDir, intf+".json")
}

func serviceProfileFile(intf string) string {
	return filepath.Join(serviceDataDir, intf+"_profile.json")
}

func InstallAndStartService(intf string, profile *config.Profile) error {
	if err := os.MkdirAll(serviceDataDir, 0755); err != nil {
		return fmt.Errorf("create service data dir: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	profileData, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	profilePath := serviceProfileFile(intf)
	if err := os.WriteFile(profilePath, profileData, 0644); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}

	cfg := serviceConfig{
		Intf:        intf,
		ProfilePath: profilePath,
	}
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	cfgPath := serviceConfigFile(intf)
	if err := os.WriteFile(cfgPath, cfgData, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	svcName := ServiceName + "$" + intf

	s, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer s.Disconnect()

	// Remove existing service if any
	if existing, err := s.OpenService(svcName); err == nil {
		existing.Control(svc.Stop)
		time.Sleep(500 * time.Millisecond)
		existing.Delete()
		existing.Close()
		time.Sleep(500 * time.Millisecond)
	}

	// Create service: awarp.exe --service <intf> <configPath>
	// SidType must be set to SERVICE_SID_TYPE_UNRESTRICTED so that Windows
	// adds the NT SERVICE SID to the service process token. The WFP firewall
	// (getCurrentProcessSecurityDescriptor) requires this SID to build the
	// security descriptor that restricts firewall-bypass filters to this
	// specific service process.
	svcHandle, err := s.CreateService(svcName, exe, mgr.Config{
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "--service", intf, cfgPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer svcHandle.Close()

	// Start service
	if err := svcHandle.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	// Wait for UAPI pipe to be available
	pipePath := `\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\` + intf
	for i := 0; i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		f, err := os.OpenFile(pipePath, os.O_RDWR, 0)
		if err == nil {
			f.Close()
			return nil
		}
	}

	return fmt.Errorf("timeout waiting for service UAPI pipe")
}

func StopAndRemoveService(intf string) error {
	svcName := ServiceName + "$" + intf

	s, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer s.Disconnect()

	svcHandle, err := s.OpenService(svcName)
	if err != nil {
		return nil
	}
	defer svcHandle.Close()

	// Try to stop
	svcHandle.Control(svc.Stop)

	// Wait for service to stop
	timeout := time.After(10 * time.Second)
	for {
		status, err := svcHandle.Query()
		if err != nil || status.State == svc.Stopped {
			break
		}
		select {
		case <-timeout:
			break
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}

	// Delete service
	if err := svcHandle.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// Cleanup files
	os.Remove(serviceConfigFile(intf))
	os.Remove(serviceProfileFile(intf))

	return nil
}

func IsServiceRunning(intf string) bool {
	svcName := ServiceName + "$" + intf

	s, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer s.Disconnect()

	svcHandle, err := s.OpenService(svcName)
	if err != nil {
		return false
	}
	defer svcHandle.Close()

	status, err := svcHandle.Query()
	if err != nil {
		return false
	}

	return status.State == svc.Running
}
