//go:build windows

package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-windows/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/tunnel/winipcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const ServiceName = "AwarpTunnel"

type warpService struct {
	intfName    string
	profilePath string
}

type serviceConfig struct {
	Intf       string `json:"intf"`
	ProfilePath string `json:"profile_path"`
}

func (s *warpService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Log to file for debugging
	logFile, err := os.Create(`C:\ProgramData\Awarp\service.log`)
	if err == nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	log.SetPrefix("[awarp-svc] ")
	log.Println("Execute called")

	cfg, err := loadServiceConfig(s.profilePath)
	if err != nil {
		log.Printf("FATAL: load config: %v", err)
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	log.Printf("Config loaded: intf=%s profile=%s", cfg.Intf, cfg.ProfilePath)

	cleanupOldAdapters()

	// Step 1: Create TUN adapter as SYSTEM
	wt, err := tun.CreateTUN(cfg.Intf, 1280)
	if err != nil {
		log.Printf("FATAL: create TUN: %v", err)
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}
	log.Println("TUN adapter created")

	// Get real interface name
	intfName := cfg.Intf
	if nt, ok := wt.(*tun.NativeTun); ok {
		if name, err := nt.Name(); err == nil {
			intfName = name
		}
	}

	// Step 2: Create WireGuard device
	bind := conn.NewDefaultBind()
	logger := &device.Logger{
		Verbosef: log.Printf,
		Errorf:   log.Printf,
	}
	dev := device.NewDevice(wt, bind, logger)

	// Step 3: Setup UAPI
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	if err == nil {
		ipc.UAPISecurityDescriptor = sd
	}

	uapi, err := ipc.UAPIListen(intfName)
	if err != nil {
		log.Printf("FATAL: UAPI listen: %v", err)
		wt.Close()
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	// Step 4: Configure device via named pipe (from CLI)
	if err := configureFromProfile(dev, cfg); err != nil {
		log.Printf("FATAL: configure: %v", err)
		uapi.Close()
		wt.Close()
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	// Step 5: Bring device up
	if err := dev.Up(); err != nil {
		log.Printf("FATAL: device up: %v", err)
		uapi.Close()
		wt.Close()
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}
	log.Println("WireGuard device is up")

	// Step 5b: Bind UDP socket to physical interface (like official client)
	if mb, ok := bind.(*conn.Multibind); ok {
		if binder, ok := mb.Bind.(conn.BindSocketToInterface); ok {
			if phyIdx := findPhysicalInterfaceIndex(wt); phyIdx != 0 {
				log.Printf("Binding socket to physical interface index %d", phyIdx)
				if err := binder.BindSocketToInterface4(phyIdx, false); err != nil {
					log.Printf("WARNING: BindSocketToInterface4: %v", err)
				}
			}
		} else {
			log.Println("WARNING: inner bind does not support BindSocketToInterface")
		}
	} else {
		log.Println("WARNING: bind is not Multibind")
	}

	// Step 5c: Enable WFP firewall (kill switch + DNS leak protection)
	if nt, ok := wt.(*tun.NativeTun); ok {
		dnsIP := net.ParseIP("1.1.1.1")
		if err := firewall.EnableFirewall(nt.LUID(), false, []net.IP{dnsIP}); err != nil {
			log.Printf("WARNING: EnableFirewall restricted: %v, trying unrestricted", err)
			firewall.DisableFirewall()
			if err2 := firewall.EnableFirewall(nt.LUID(), true, nil); err2 != nil {
				log.Printf("WARNING: EnableFirewall unrestricted: %v", err2)
			} else {
				log.Println("WFP firewall enabled (unrestricted)")
			}
		} else {
			log.Println("WFP firewall enabled (restricted)")
		}
	}

	// Step 6: Configure network (IP, routes, DNS) via winipcfg like official client
	if nt, ok := wt.(*tun.NativeTun); ok {
		if err := configureNetworkWinipcfg(nt, cfg); err != nil {
			log.Printf("WARNING: network config: %v", err)
		}
	} else {
		log.Printf("WARNING: cannot get NativeTun for network config")
	}

	// Step 7: Accept UAPI connections
	go func() {
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Println("Service running, waiting for stop...")

	// Step 8: Wait for stop signal
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				log.Println("Stop received")
				goto cleanup
			case svc.Interrogate:
				changes <- c.CurrentStatus
			}
		case <-dev.Wait():
			log.Println("Device exited")
			goto cleanup
		}
	}

cleanup:
	log.Println("Cleaning up...")
	firewall.DisableFirewall()
	uapi.Close()
	wt.Close()
	log.Println("Stopped")
	return false, 0
}

func loadServiceConfig(path string) (*serviceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg serviceConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func configureFromProfile(dev *device.Device, cfg *serviceConfig) error {
	// Read the profile JSON and extract UAPI commands
	// The profile contains all the WireGuard config we need
	profileData, err := os.ReadFile(cfg.ProfilePath)
	if err != nil {
		return fmt.Errorf("read profile: %w", err)
	}

	var profile struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		Address    string `json:"address"`
		Endpoint   string `json:"endpoint"`
		AWG        struct {
			Jc   int    `json:"jc"`
			Jmin int    `json:"jmin"`
			Jmax int    `json:"jmax"`
			S1   int    `json:"s1"`
			S2   int    `json:"s2"`
			H1   string `json:"h1"`
			H2   string `json:"h2"`
			H3   string `json:"h3"`
			H4   string `json:"h4"`
			I1   string `json:"i1"`
			I2   string `json:"i2"`
			I3   string `json:"i3"`
			I4   string `json:"i4"`
			I5   string `json:"i5"`
		} `json:"awg"`
	}

	if err := json.Unmarshal(profileData, &profile); err != nil {
		return fmt.Errorf("parse profile: %w", err)
	}

	// Resolve endpoint
	host := profile.Endpoint
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":2408"
	}
	hostIP, port, _ := net.SplitHostPort(host)
	if net.ParseIP(hostIP) == nil {
		ips, err := net.LookupHost(hostIP)
		if err == nil && len(ips) > 0 {
			hostIP = ips[0]
		}
	}

	// Build UAPI set command — device-level keys first, then peer
	privHex, err := b64toHex(profile.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	pubHex, err := b64toHex(profile.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	// Device-level: private key + obfuscation params
	cmd := "private_key=" + privHex
	if profile.AWG.Jc != 0 {
		cmd += fmt.Sprintf("\njc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d",
			profile.AWG.Jc, profile.AWG.Jmin, profile.AWG.Jmax, profile.AWG.S1, profile.AWG.S2)
	}
	for _, h := range []struct{ name, val string }{
		{"h1", profile.AWG.H1}, {"h2", profile.AWG.H2},
		{"h3", profile.AWG.H3}, {"h4", profile.AWG.H4},
	} {
		if h.val != "" && h.val != "0" {
			cmd += fmt.Sprintf("\n%s=%s", h.name, h.val)
		}
	}
	for i, v := range []string{profile.AWG.I1, profile.AWG.I2, profile.AWG.I3, profile.AWG.I4, profile.AWG.I5} {
		if v != "" {
			cmd += fmt.Sprintf("\ni%d=%s", i+1, v)
		}
	}

	// Peer section
	cmd += fmt.Sprintf("\nreplace_peers=true\npublic_key=%s\nendpoint=%s:%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25",
		pubHex, hostIP, port)

	return dev.IpcSet(cmd)
}

// findPhysicalInterfaceIndex finds the physical interface index (lowest metric default route, excluding TUN)
func findPhysicalInterfaceIndex(tunDev tun.Device) uint32 {
	ourLUID := winipcfg.LUID(0)
	if nt, ok := tunDev.(*tun.NativeTun); ok {
		ourLUID = winipcfg.LUID(nt.LUID())
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		log.Printf("WARNING: GetIPForwardTable2: %v", err)
		return 0
	}

	lowestMetric := ^uint32(0)
	bestIndex := uint32(0)

	for i := range routes {
		r := &routes[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		if r.InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := r.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		iface, err := r.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}
		total := r.Metric + iface.Metric
		if total < lowestMetric {
			lowestMetric = total
			bestIndex = r.InterfaceIndex
		}
	}
	return bestIndex
}

func configureNetworkWinipcfg(nativeTun *tun.NativeTun, cfg *serviceConfig) error {
	profileData, err := os.ReadFile(cfg.ProfilePath)
	if err != nil {
		return err
	}

	var profile struct {
		Address  string `json:"address"`
		Address6 string `json:"address6"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(profileData, &profile); err != nil {
		return err
	}
	if profile.Address == "" {
		return nil
	}

	luid := winipcfg.LUID(nativeTun.LUID())

	// Parse IPv4 address
	addrStr := profile.Address
	cidr := 32
	if idx := strings.Index(addrStr, "/"); idx != -1 {
		fmt.Sscanf(addrStr[idx+1:], "%d", &cidr)
		addrStr = addrStr[:idx]
	}
	ip := net.ParseIP(addrStr)
	if ip == nil {
		return fmt.Errorf("invalid address: %s", addrStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", addrStr)
	}

	// Set IPv4 address
	addresses := []net.IPNet{{IP: ip4, Mask: net.CIDRMask(cidr, 32)}}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, addresses); err != nil {
		if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
			luid.DeleteIPAddress(addresses[0])
			luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
		} else {
			log.Printf("WARNING: SetIPv4: %v", err)
		}
	}
	log.Printf("Set IP %s/%d on TUN", addrStr, cidr)

	// Set DNS on TUN
	dnsServers := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")}
	if err := luid.SetDNS(windows.AF_INET, dnsServers, nil); err != nil {
		log.Printf("WARNING: SetDNS v4: %v", err)
	}
	log.Println("Set DNS 1.1.1.1, 1.0.0.1 on TUN")

	// Set default route (metric 0) + endpoint host route
	gw := getDefaultGateway()
	routes := []*winipcfg.RouteData{
		{
			Destination: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			NextHop:     net.IPv4zero,
			Metric:      0,
		},
	}

	// Resolve endpoint for host route
	host := profile.Endpoint
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":2408"
	}
	hostIP, _, _ := net.SplitHostPort(host)
	if net.ParseIP(hostIP) == nil {
		ips, err := net.LookupHost(hostIP)
		if err == nil && len(ips) > 0 {
			hostIP = ips[0]
		}
	}

	// Host route to endpoint via physical gateway
	if hostIP != "" && gw != "" {
		routes = append(routes, &winipcfg.RouteData{
			Destination: net.IPNet{IP: net.ParseIP(hostIP), Mask: net.CIDRMask(32, 32)},
			NextHop:     net.ParseIP(gw),
			Metric:      0,
		})
	}

	if err := luid.SetRoutesForFamily(windows.AF_INET, routes); err != nil {
		log.Printf("WARNING: SetRoutes v4: %v", err)
	}
	log.Println("Set default route via TUN (metric 0)")

	// Set interface metric to 0 (like official client)
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		ipif.Set()
	}

	// IPv6 if available
	if profile.Address6 != "" {
		addr6Str := profile.Address6
		cidr6 := 128
		if idx := strings.Index(addr6Str, "/"); idx != -1 {
			fmt.Sscanf(addr6Str[idx+1:], "%d", &cidr6)
			addr6Str = addr6Str[:idx]
		}
		ip6 := net.ParseIP(addr6Str)
		if ip6 != nil && ip6.To4() == nil {
			addresses6 := []net.IPNet{{IP: ip6, Mask: net.CIDRMask(cidr6, 128)}}
			if err := luid.SetIPAddressesForFamily(windows.AF_INET6, addresses6); err != nil {
				if err != windows.ERROR_OBJECT_ALREADY_EXISTS {
					log.Printf("WARNING: SetIPv6: %v", err)
				}
			}
			dns6 := []net.IP{net.ParseIP("2606:4700:4700::1111"), net.ParseIP("2606:4700:4700::1001")}
			luid.SetDNS(windows.AF_INET6, dns6, nil)

			routes6 := []*winipcfg.RouteData{
				{
					Destination: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
					NextHop:     net.IPv6zero,
					Metric:      0,
				},
			}
			luid.SetRoutesForFamily(windows.AF_INET6, routes6)

			if ipif, err := luid.IPInterface(windows.AF_INET6); err == nil {
				ipif.UseAutomaticMetric = false
				ipif.Metric = 0
				ipif.DadTransmits = 0
				ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
				ipif.Set()
			}
			log.Printf("Set IPv6 %s/%d on TUN", addr6Str, cidr6)
		}
	}

	log.Printf("Network configured via winipcfg: %s on TUN", addrStr)
	return nil
}

func configureNetwork(intfName string, cfg *serviceConfig) error {
	// Read profile for address
	profileData, err := os.ReadFile(cfg.ProfilePath)
	if err != nil {
		return err
	}

	var profile struct {
		Address  string `json:"address"`
		Address6 string `json:"address6"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(profileData, &profile); err != nil {
		return err
	}

	if profile.Address == "" {
		return nil
	}

	addr := profile.Address
	if i, _ := fmt.Sscanf(addr, "%d.%d.%d.%d", new(int), new(int), new(int), new(int)); i != 4 {
		// addr has CIDR, strip it
		for j, c := range addr {
			if c == '/' {
				addr = addr[:j]
				break
			}
		}
	}

	gw := getDefaultGateway()

	// Set IP
	runCmd(fmt.Sprintf(`netsh interface ip set address "%s" static %s 255.255.255.255`, intfName, addr))

	// Set DNS
	runCmd(fmt.Sprintf(`netsh interface ip set dns "%s" static 1.1.1.1 register=primary`, intfName))

	// Resolve endpoint for host route
	host := profile.Endpoint
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":2408"
	}
	hostIP, _, _ := net.SplitHostPort(host)
	if net.ParseIP(hostIP) == nil {
		ips, err := net.LookupHost(hostIP)
		if err == nil && len(ips) > 0 {
			hostIP = ips[0]
		}
	}

	// Route to endpoint via original gateway
	if hostIP != "" && gw != "" {
		runCmd(fmt.Sprintf(`route add %s mask 255.255.255.255 %s`, hostIP, gw))
	}

	// Default route via TUN (metric=0 like official client)
	runCmd(fmt.Sprintf(`netsh interface ip add route 0.0.0.0/0 "%s" %s metric=0 store=active`, intfName, addr))

	// IPv6
	if profile.Address6 != "" {
		addr6 := profile.Address6
		for j, c := range addr6 {
			if c == '/' {
				addr6 = addr6[:j]
				break
			}
		}
		runCmd(fmt.Sprintf(`netsh interface ipv6 set address "%s" %s`, intfName, addr6))
		runCmd(fmt.Sprintf(`netsh interface ipv6 set dns "%s" static 2606:4700:4700::1111`, intfName))
		runCmd(fmt.Sprintf(`netsh interface ipv6 add route ::/0 "%s" %s metric=0 store=active`, intfName, addr6))
	}

	log.Printf("Network configured: %s on %s", addr, intfName)
	return nil
}

// RunService is called from main.go when --service flag is present
func RunService(intfName, profilePath string) error {
	svcName := ServiceName
	if intfName != "" {
		svcName = ServiceName + "$" + intfName
	}
	return svc.Run(svcName, &warpService{intfName: intfName, profilePath: profilePath})
}
