package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"warp-cli/config"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/ipc/namedpipe"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-windows/tunnel/winipcfg"
	"golang.org/x/sys/windows"
)

func runCmd(cmd string) error {
	c := exec.Command("cmd", "/c", cmd)
	return c.Run()
}

func runCmdOutput(cmd string) (string, error) {
	c := exec.Command("cmd", "/c", cmd)
	out, err := c.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func getDefaultGateway() string {
	out, err := runCmdOutput(`route print 0.0.0.0`)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				gw := fields[2]
				if ip := net.ParseIP(gw); ip != nil && !ip.Equal(net.IPv4zero) {
					return gw
				}
			}
		}
	}
	return ""
}

func getPhysicalIntf() string {
	out, err := runCmdOutput(`netsh interface ip show config`)
	if err != nil {
		return ""
	}
	var currentName string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Configuration for interface") {
			parts := strings.SplitN(line, "\"", 3)
			if len(parts) >= 2 {
				currentName = parts[1]
			}
		}
		if strings.Contains(line, "Default Gateway") && !strings.Contains(line, "none") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
					return currentName
				}
			}
		}
	}
	return ""
}

func getInterfaceDNS(intf string) string {
	out, err := runCmdOutput(fmt.Sprintf(`netsh interface ip show dns "%s"`, intf))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Statically Configured DNS Servers") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				dns := strings.TrimSpace(parts[1])
				if ip := net.ParseIP(dns); ip != nil {
					return dns
				}
			}
		}
	}
	return ""
}

// cleanupOldAdapters is defined in adapter_cleanup.go

func b64toHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

type Tunnel struct {
	dev         *device.Device
	tun         tun.Device
	softTun     *SoftTun
	uapi        net.Listener
	logger      *device.Logger
	intf        string
	stopCh      chan os.Signal
	closeOnce   sync.Once
	origGW      string
	tunnelAddr  string
	endpointIP  string
	phyIntf     string
	phyDNS      string
	profileName string
}

type tunnelState struct {
	OrigGW     string `json:"orig_gw"`
	TunnelAddr string `json:"tunnel_addr"`
	EndpointIP string `json:"endpoint_ip"`
	Intf       string `json:"intf"`
	PhyIntf    string `json:"phy_intf"`
	PhyDNS     string `json:"phy_dns"`
}

func statePath(profile string) string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	if profile == "" {
		return filepath.Join(dir, "tunnel.state")
	}
	return filepath.Join(dir, fmt.Sprintf("tunnel_%s.state", profile))
}

func saveState(profile string, s tunnelState) error {
	data, _ := json.Marshal(s)
	return os.WriteFile(statePath(profile), data, 0600)
}

func loadState(profile string) (tunnelState, error) {
	var s tunnelState
	data, err := os.ReadFile(statePath(profile))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

func New(name string, profileName string) *Tunnel {
	return &Tunnel{
		intf:        name,
		profileName: profileName,
		stopCh:      make(chan os.Signal, 1),
	}
}

func (t *Tunnel) Start(profile *config.Profile) error {
	t.logger = device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", t.intf),
	)

	cleanupOldAdapters()

	var err error
	t.tun, err = tun.CreateTUN(t.intf, 1280)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}

	t.softTun = newSoftTun(t.tun)

	realName, err := t.tun.Name()
	if err == nil {
		t.intf = realName
	}

	t.dev = device.NewDevice(t.softTun, conn.NewDefaultBind(), t.logger)

	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	if err != nil {
		t.dev.Close()
		t.tun.Close()
		return fmt.Errorf("create security descriptor: %w", err)
	}
	ipc.UAPISecurityDescriptor = sd

	t.uapi, err = ipc.UAPIListen(t.intf)
	if err != nil {
		t.dev.Close()
		t.tun.Close()
		return fmt.Errorf("uapi listen: %w", err)
	}

	go func() {
		for {
			conn, err := t.uapi.Accept()
			if err != nil {
				return
			}
			go t.dev.IpcHandle(conn)
		}
	}()

	if err := t.configure(profile); err != nil {
		t.Close()
		return fmt.Errorf("configure: %w", err)
	}

	if err := t.dev.Up(); err != nil {
		t.Close()
		return fmt.Errorf("device up: %w", err)
	}

	// Bind UDP socket to physical interface (like official client)
	if mb, ok := t.dev.Bind().(*conn.Multibind); ok {
		if binder, ok := mb.Bind.(conn.BindSocketToInterface); ok {
			if phyIdx := findPhysicalInterfaceIndex(t.tun); phyIdx != 0 {
				t.logger.Verbosef("Binding socket to physical interface index %d", phyIdx)
				if err := binder.BindSocketToInterface4(phyIdx, false); err != nil {
					t.logger.Verbosef("WARNING: BindSocketToInterface4: %v", err)
				}
			}
		}
	}

	if profile.Address != "" {
		addr := strings.Split(profile.Address, "/")[0]

		gw := getDefaultGateway()
		t.origGW = gw
		t.tunnelAddr = addr
		t.logger.Verbosef("Original default gateway: %s", gw)

		// Minimal setup — same as official AmneziaWG client
		// 1. Set IP on TUN
		runCmd(fmt.Sprintf(`netsh interface ip set address "%s" static %s 255.255.255.255`, t.intf, addr))
		t.logger.Verbosef("Set IP %s on %s", addr, t.intf)

		// 2. Set DNS on TUN
		runCmd(fmt.Sprintf(`netsh interface ip set dns "%s" static 1.1.1.1 register=primary`, t.intf))
		t.logger.Verbosef("Set DNS on %s", t.intf)

		// 3. Resolve endpoint
		host := profile.Endpoint
		if !strings.Contains(host, ":") {
			host = host + ":2408"
		}
		hostIP, _, _ := net.SplitHostPort(host)
		if net.ParseIP(hostIP) == nil {
			ips, err := net.LookupHost(hostIP)
			if err == nil {
				for _, ip := range ips {
					if p := net.ParseIP(ip); p != nil && p.To4() != nil {
						hostIP = ip
						break
					}
				}
				if hostIP == "" && len(ips) > 0 {
					hostIP = ips[0]
				}
			}
		}
		t.endpointIP = hostIP
		t.logger.Verbosef("Endpoint IP: %s", hostIP)

		// 4. Route to endpoint via original gateway (bypasses TUN)
		if hostIP != "" && gw != "" {
			runCmd(fmt.Sprintf(`route add %s mask 255.255.255.255 %s`, hostIP, gw))
			t.logger.Verbosef("Added endpoint route: %s via %s", hostIP, gw)
		}

		// 5. Default route via TUN
		runCmd(fmt.Sprintf(`netsh interface ip add route 0.0.0.0/0 "%s" %s metric=0 store=active`, t.intf, addr))
		t.logger.Verbosef("Added default route via %s on %s", addr, t.intf)

		// 6. IPv6 (optional)
		if profile.Address6 != "" {
			addr6 := strings.Split(profile.Address6, "/")[0]
			runCmd(fmt.Sprintf(`netsh interface ipv6 set address "%s" %s`, t.intf, addr6))
			runCmd(fmt.Sprintf(`netsh interface ipv6 set dns "%s" static 2606:4700:4700::1111`, t.intf))
			runCmd(fmt.Sprintf(`netsh interface ipv6 add route ::/0 "%s" %s metric=0 store=active`, t.intf, addr6))
		}

		time.Sleep(500 * time.Millisecond)
		verifyOutput, err := runCmdOutput(`route print`)
		if err == nil {
			t.logger.Verbosef("Route table after setup:\n%s", verifyOutput)
		}

		saveState(t.profileName, tunnelState{
			OrigGW:     t.origGW,
			TunnelAddr: t.tunnelAddr,
			EndpointIP: t.endpointIP,
			Intf:       t.intf,
		})
	}

	return nil
}

func (t *Tunnel) configure(profile *config.Profile) error {
	pipeName := fmt.Sprintf(`\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\%s`, t.intf)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := namedpipe.DialContext(ctx, pipeName)
	if err != nil {
		return fmt.Errorf("dial uapi pipe: %w", err)
	}
	defer conn.Close()

	var cmd strings.Builder
	cmd.WriteString("set=1\n")

	privHex, err := b64toHex(profile.PrivateKey)
	if err != nil {
		return fmt.Errorf("convert private key to hex: %w", err)
	}
	fmt.Fprintf(&cmd, "private_key=%s\n", privHex)

	awg := profile.AWG
	fmt.Fprintf(&cmd, "jc=%d\n", awg.Jc)
	fmt.Fprintf(&cmd, "jmin=%d\n", awg.Jmin)
	fmt.Fprintf(&cmd, "jmax=%d\n", awg.Jmax)
	fmt.Fprintf(&cmd, "s1=%d\n", awg.S1)
	fmt.Fprintf(&cmd, "s2=%d\n", awg.S2)
	if awg.H1 != "" && awg.H1 != "0" {
		fmt.Fprintf(&cmd, "h1=%s\n", awg.H1)
	}
	if awg.H2 != "" && awg.H2 != "0" {
		fmt.Fprintf(&cmd, "h2=%s\n", awg.H2)
	}
	if awg.H3 != "" && awg.H3 != "0" {
		fmt.Fprintf(&cmd, "h3=%s\n", awg.H3)
	}
	if awg.H4 != "" && awg.H4 != "0" {
		fmt.Fprintf(&cmd, "h4=%s\n", awg.H4)
	}
	for i, v := range []string{awg.I1, awg.I2, awg.I3, awg.I4, awg.I5} {
		if v != "" {
			fmt.Fprintf(&cmd, "i%d=%s\n", i+1, v)
		}
	}

	pubHex, err := b64toHex(profile.PublicKey)
	if err != nil {
		return fmt.Errorf("convert public key to hex: %w", err)
	}
	fmt.Fprintf(&cmd, "public_key=%s\n", pubHex)

	host := profile.Endpoint
	if !strings.Contains(host, ":") {
		host = host + ":2408"
	}
	hostIP, port, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("parse endpoint: %w", err)
	}
	if net.ParseIP(hostIP) == nil {
		ips, err := net.LookupHost(hostIP)
		if err == nil && len(ips) > 0 {
			hostIP = ips[0]
		}
	}
	fmt.Fprintf(&cmd, "endpoint=%s:%s\n", hostIP, port)

	cmd.WriteString("allowed_ip=0.0.0.0/0\n")
	cmd.WriteString("allowed_ip=::/0\n")
	cmd.WriteString("persistent_keepalive_interval=25\n")
	cmd.WriteString("\n")

	if _, err := conn.Write([]byte(cmd.String())); err != nil {
		return fmt.Errorf("write uapi config: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read uapi response: %w", err)
	}

	resp := strings.TrimSpace(string(buf[:n]))
	if resp != "OK" && !strings.HasPrefix(resp, "errno=0") {
		return fmt.Errorf("uapi config failed: %s", resp)
	}

	return nil
}

func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		// Step 1: Flush TUN routes/IPs/DNS (like amneziawg-windows-client)
		if t.tun != nil {
			if nativeTun, ok := t.tun.(*tun.NativeTun); ok {
				luid := winipcfg.LUID(nativeTun.LUID())
				luid.FlushRoutes(windows.AF_INET)
				luid.FlushIPAddresses(windows.AF_INET)
				luid.FlushDNS(windows.AF_INET)
				luid.FlushRoutes(windows.AF_INET6)
				luid.FlushIPAddresses(windows.AF_INET6)
				luid.FlushDNS(windows.AF_INET6)
				t.logger.Verbosef("Flushed TUN routes/IPs/DNS")
			}
		}

		// Step 2: Close UAPI listener
		if t.uapi != nil {
			t.uapi.Close()
		}

		// Step 3: Close device (destroys TUN adapter)
		if t.dev != nil {
			done := make(chan struct{})
			go func() {
				t.dev.Close()
				close(done)
			}()
			select {
			case <-done:
				t.logger.Verbosef("Device closed gracefully")
			case <-time.After(3 * time.Second):
				t.logger.Verbosef("Device close timed out, forcing")
			}
		}

		t.logger.Verbosef("Tunnel closed")

		// Step 4: Delete state file
		os.Remove(statePath(t.profileName))

		// Step 5: Cleanup endpoint route
		if t.endpointIP != "" {
			runCmd(fmt.Sprintf(`route delete %s mask 255.255.255.255`, t.endpointIP))
		}
	})
}

func (t *Tunnel) restorePhysicalDNS(phyIntf, phyDNS string) {
	if phyIntf == "" {
		return
	}
	runCmd(fmt.Sprintf(`netsh interface ipv6 set interface "%s" enable`, phyIntf))
	t.logger.Verbosef("Restored IPv6 on physical adapter %s", phyIntf)
	if phyDNS != "" {
		t.logger.Verbosef("Restoring DNS on physical adapter %s to %s", phyIntf, phyDNS)
		runCmd(fmt.Sprintf(`netsh interface ip set dns "%s" static %s`, phyIntf, phyDNS))
	} else {
		t.logger.Verbosef("Resetting DNS on physical adapter %s to DHCP", phyIntf)
		runCmd(fmt.Sprintf(`netsh interface ip set dns "%s" dhcp`, phyIntf))
	}
}

func CleanupTunnel(profile string) {
	SignalStop(profile)

	// Wait for running process to cleanup (it removes state file)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(statePath(profile)); os.IsNotExist(err) {
			return // running process cleaned up
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Fallback: do cleanup ourselves if running process didn't
	s, err := loadState(profile)
	if err != nil {
		return
	}
	t := &Tunnel{
		origGW:      s.OrigGW,
		tunnelAddr:  s.TunnelAddr,
		endpointIP:  s.EndpointIP,
		intf:        s.Intf,
		profileName: profile,
		logger:      device.NewLogger(device.LogLevelVerbose, "(cleanup) "),
	}

	// Delete TUN-specific routes
	runCmd(fmt.Sprintf(`netsh interface ip delete route 0.0.0.0/0 "%s" 172.16.0.2`, s.Intf))
	runCmd(fmt.Sprintf(`netsh interface ipv6 delete route ::/0 "%s"`, s.Intf))
	if s.EndpointIP != "" {
		runCmd(fmt.Sprintf(`route delete %s mask 255.255.255.255`, s.EndpointIP))
	}

	// Restore registry settings
	runCmd(`reg delete "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /f`)
	runCmd(`reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v NoActiveProbe /f`)
	runCmd(`reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v ConnectivityStatus /f`)
	runCmd(`reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableSmartNameResolution /f`)

	// Restore DNS
	t.restorePhysicalDNS(s.PhyIntf, s.PhyDNS)
	runCmd(`ipconfig /flushdns`)

	os.Remove(statePath(profile))
}

func stopPath(profile string) string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	if profile == "" {
		return filepath.Join(dir, "tunnel.stop")
	}
	return filepath.Join(dir, fmt.Sprintf("tunnel_%s.stop", profile))
}

func SignalStop(profile string) {
	os.WriteFile(stopPath(profile), []byte("stop"), 0600)
}

func (t *Tunnel) Wait() {
	signal.Notify(t.stopCh, os.Interrupt)

	// Check if stop was already requested before we started
	if _, err := os.Stat(stopPath(t.profileName)); err == nil {
		t.logger.Verbosef("Stop signal already pending")
		t.Close()
		os.Remove(stopPath(t.profileName))
		return
	}

	go func() {
		for {
			if _, err := os.Stat(stopPath(t.profileName)); err == nil {
				t.logger.Verbosef("Stop signal received")
				select {
				case t.stopCh <- os.Interrupt:
				default:
				}
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	sig := <-t.stopCh
	t.logger.Verbosef("Received signal %v, shutting down...", sig)
	t.Close()
	os.Remove(stopPath(t.profileName))
}

func (t *Tunnel) InterfaceName() string {
	return t.intf
}

func Status(profile *config.Profile) error {
	pipeName := fmt.Sprintf(`\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\warp0`)

	conn, err := namedpipe.DialTimeout(pipeName, 3*time.Second)
	if err != nil {
		return fmt.Errorf("not connected or access denied: %w", err)
	}
	defer conn.Close()

	cmd := "get=1\n\n"
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return fmt.Errorf("write get request: %w", err)
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read status: %w", err)
	}

	fmt.Println(string(buf[:n]))
	return nil
}

func UAPICommand(name string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("uapi command required")
	}

	pipeName := fmt.Sprintf(`\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\%s`, name)

	conn, err := namedpipe.DialTimeout(pipeName, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial uapi: %w", err)
	}
	defer conn.Close()

	action := args[0]
	var cmd string
	switch action {
	case "set":
		cmd = "set=1\n"
		for _, arg := range args[1:] {
			cmd += arg + "\n"
		}
		cmd += "\n"
	case "get":
		cmd = "get=1\n\n"
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	if _, err := conn.Write([]byte(cmd)); err != nil {
		return fmt.Errorf("write uapi: %w", err)
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read uapi response: %w", err)
	}

	fmt.Println(string(buf[:n]))
	return nil
}

func ParseAWGArgs(args []string) (config.AWGConfig, error) {
	awg := config.DefaultAWG
	for _, arg := range args {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(kv[0])
		val := kv[1]

		switch key {
		case "jc":
			v, err := strconv.Atoi(val)
			if err != nil {
				return awg, fmt.Errorf("invalid value for %s: %q is not a number", key, val)
			}
			awg.Jc = v
		case "jmin":
			v, err := strconv.Atoi(val)
			if err != nil {
				return awg, fmt.Errorf("invalid value for %s: %q is not a number", key, val)
			}
			awg.Jmin = v
		case "jmax":
			v, err := strconv.Atoi(val)
			if err != nil {
				return awg, fmt.Errorf("invalid value for %s: %q is not a number", key, val)
			}
			awg.Jmax = v
		case "s1":
			v, err := strconv.Atoi(val)
			if err != nil {
				return awg, fmt.Errorf("invalid value for %s: %q is not a number", key, val)
			}
			awg.S1 = v
		case "s2":
			v, err := strconv.Atoi(val)
			if err != nil {
				return awg, fmt.Errorf("invalid value for %s: %q is not a number", key, val)
			}
			awg.S2 = v
		case "s3":
			// not supported in v1.0.4, silently ignore
		case "s4":
			// not supported in v1.0.4, silently ignore
		case "h1":
			if val == "0" {
				awg.H1 = ""
			} else {
				awg.H1 = val
			}
		case "h2":
			if val == "0" {
				awg.H2 = ""
			} else {
				awg.H2 = val
			}
		case "h3":
			if val == "0" {
				awg.H3 = ""
			} else {
				awg.H3 = val
			}
		case "h4":
			if val == "0" {
				awg.H4 = ""
			} else {
				awg.H4 = val
			}
		case "i1":
			awg.I1 = val
		case "i2":
			awg.I2 = val
		case "i3":
			awg.I3 = val
		case "i4":
			awg.I4 = val
		case "i5":
			awg.I5 = val
		default:
			return awg, fmt.Errorf("unknown AWG param: %s", key)
		}
	}
	return awg, nil
}
