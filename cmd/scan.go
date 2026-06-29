package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"warp-cli/config"
	"warp-cli/warp"
)

const (
	scanConcurrency  = 50
	scanTopN         = 20
	scanPingTimeout  = 500 // ms
	scanProbeTimeout = 3 * time.Second
)

var scanSubnets = []string{
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
}

var scanPortList = []int{
	2408, 500, 1701, 4500,
	854, 859, 864, 878, 880, 890, 894, 903, 942, 943,
	945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018,
	1070, 1074, 1180, 1387, 1843, 2371, 2506, 3476, 3581,
	3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156,
	7281, 8886,
}

var fastPorts = []int{2408, 500, 1701, 4500, 1002, 7281, 3581, 878}

type ScanResult struct {
	IP          string
	Port        int
	Latency     time.Duration
	InCommunity bool
	CommLatency float64
}

type ipLatency struct {
	ip        string
	latency   time.Duration
	reachable bool
}

type udpProbeResult struct {
	ip    string
	port  int
	alive bool
}

type communityEndpoint struct {
	IP   string  `json:"ip"`
	Port int     `json:"port"`
	Ping float64 `json:"ping"`
}

// scanAliveEndpoints runs ICMP ping + UDP WireGuard handshake probe on the given IPs
// and returns alive endpoints sorted by latency. Keys can be empty for MAC1-only fallback.
// If awgCfg is non-nil, uses AmneziaWG obfuscation (junk + I1-I5 frames + padding).
func scanAliveEndpoints(ips []string, ports []int, clientPrivB64, serverPubB64 string, commEPs map[string]communityEndpoint, awgCfg *config.AWGConfig) []ScanResult {
	// Phase 1: ICMP ping
	var results []ipLatency
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, scanConcurrency)
	fmt.Print("  Phase 1: Pinging IPs...")
	var doneCount int
	var aliveCount int

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			lat, ok := icmpPing(ip)
			mu.Lock()
			results = append(results, ipLatency{ip: ip, latency: lat, reachable: ok})
			doneCount++
			if ok {
				aliveCount++
			}
			if doneCount%50 == 0 || doneCount == len(ips) {
				fmt.Printf("\r  Phase 1: Pinging IPs... [%d/%d] (%d alive)", doneCount, len(ips), aliveCount)
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	fmt.Printf("\r  Phase 1: Pinging IPs... [%d/%d] (%d alive)\n", len(ips), len(ips), aliveCount)

	var reachable []ipLatency
	for _, r := range results {
		if r.reachable {
			reachable = append(reachable, r)
		}
	}

	if len(reachable) == 0 {
		return nil
	}

	sort.Slice(reachable, func(i, j int) bool {
		return reachable[i].latency < reachable[j].latency
	})

	// Phase 2: Probe UDP ports via real WireGuard handshake
	limit := 30
	if limit > len(reachable) {
		limit = len(reachable)
	}

	fmt.Printf("  Phase 2: Checking UDP ports on top %d IPs...\n", limit)

	var probeResults []udpProbeResult
	var mu2 sync.Mutex
	var wg2 sync.WaitGroup
	sem2 := make(chan struct{}, scanConcurrency)
	totalProbes := limit * len(ports)
	var probeDone int

	for _, r := range reachable[:limit] {
		for _, port := range ports {
			wg2.Add(1)
			sem2 <- struct{}{}
			go func(ip string, port int, privKey, pubKey string) {
				defer wg2.Done()
				defer func() { <-sem2 }()
				var alive bool
				if privKey != "" {
					if awgCfg != nil {
						alive = udpProbeAWG(ip, port, privKey, pubKey, *awgCfg)
					} else {
						alive = udpProbeRegistered(ip, port, privKey, pubKey)
					}
				} else {
					alive = udpProbe(ip, port)
				}
				mu2.Lock()
				probeResults = append(probeResults, udpProbeResult{ip: ip, port: port, alive: alive})
				probeDone++
				if probeDone%50 == 0 || probeDone == totalProbes {
					fmt.Printf("\r  Phase 2: [%d/%d]", probeDone, totalProbes)
				}
				mu2.Unlock()
			}(r.ip, port, clientPrivB64, serverPubB64)
		}
	}
	wg2.Wait()
	fmt.Printf("\r  Phase 2: [%d/%d] done\n", totalProbes, totalProbes)

	ipBestPort := make(map[string]int)
	for _, p := range probeResults {
		if !p.alive {
			continue
		}
		existing := ipBestPort[p.ip]
		if existing == 0 || p.port == 2408 {
			ipBestPort[p.ip] = p.port
		}
	}

	var scanResults []ScanResult
	for _, r := range reachable[:limit] {
		port, ok := ipBestPort[r.ip]
		if !ok {
			continue
		}
		sr := ScanResult{
			IP:      r.ip,
			Port:    port,
			Latency: r.latency,
		}
		if ce, found := commEPs[r.ip]; found {
			sr.InCommunity = true
			sr.CommLatency = ce.Ping
		}
		scanResults = append(scanResults, sr)
	}

	sort.Slice(scanResults, func(i, j int) bool {
		return scanResults[i].Latency < scanResults[j].Latency
	})

	return scanResults
}

func ScanEndpoints(community, fast, useAWG bool) error {
	ports := scanPortList
	if fast {
		ports = fastPorts
	}
	fmt.Printf("Scanning Cloudflare WARP endpoints (%d subnets)\n", len(scanSubnets))
	for _, s := range scanSubnets {
		fmt.Printf("  %s\n", s)
	}
	fmt.Printf("Ports:  %d%s\n", len(ports), map[bool]string{true: " (fast mode)"}[fast])
	fmt.Printf("Method: ICMP ping + WireGuard handshake probe\n")
	fmt.Println()

	var commEPs map[string]communityEndpoint
	if community {
		fmt.Print("Fetching community endpoint lists...")
		commEPs = fetchCommunityEndpoints()
		if len(commEPs) > 0 {
			fmt.Printf(" got %d endpoints\n", len(commEPs))
		} else {
			fmt.Println(" none found, falling back to full scan")
		}
		fmt.Println()
	}

	var ips []string
	if community && len(commEPs) > 0 {
		for ip := range commEPs {
			ips = append(ips, ip)
		}
	} else {
		ips = generateIPs()
	}

	// Load profile keys for proper WG handshake (fall back to no-MAC1 probe)
	profile, _ := config.LoadProfile("warp")
	hasKeys := profile != nil && profile.PrivateKey != "" && profile.PublicKey != ""
	if hasKeys {
		fmt.Printf("Using profile %q for WireGuard handshake\n", profile.Name)
	} else {
		fmt.Println("No profile found, using MAC1-only probe (may miss idle servers)")
	}
	fmt.Println()

	fmt.Printf("Scanning %d IPs...\n\n", len(ips))

	clientPrivB64, serverPubB64 := "", ""
	if hasKeys {
		clientPrivB64 = profile.PrivateKey
		serverPubB64 = profile.PublicKey
	}

	// AWG config
	var awgCfg *config.AWGConfig
	if useAWG && hasKeys {
		if profile.AWG.Jc > 0 || profile.AWG.I1 != "" {
			awgCfg = &profile.AWG
			fmt.Println("Using AmneziaWG obfuscation from profile")
		} else {
			def := config.DefaultAWG
			awgCfg = &def
			fmt.Println("Using default AmneziaWG obfuscation")
		}
	}
	if useAWG && !hasKeys {
		fmt.Println("Warning: --awg requires a registered profile, falling back to plain WG")
	}

	scanResults := scanAliveEndpoints(ips, ports, clientPrivB64, serverPubB64, commEPs, awgCfg)

	// Fallback chain:
	// 1. AWG → plain WG if AWG found nothing
	if len(scanResults) == 0 && awgCfg != nil {
		fmt.Println("No endpoints with AWG, retrying with plain WireGuard handshake...")
		scanResults = scanAliveEndpoints(ips, ports, clientPrivB64, serverPubB64, commEPs, nil)
	}

	// 2. Profile key → default WARP key if profile key differs
	if len(scanResults) == 0 && hasKeys && serverPubB64 != warpServerPubKeyB64 {
		fmt.Println("No endpoints with profile key, retrying with default WARP key...")
		scanResults = scanAliveEndpoints(ips, ports, clientPrivB64, warpServerPubKeyB64, commEPs, nil)
	}

	if len(scanResults) == 0 {
		fmt.Println("No responding WARP endpoints found.")
		return nil
	}

	outLimit := scanTopN
	if outLimit > len(scanResults) {
		outLimit = len(scanResults)
	}

	subnetCount := make(map[string]int)
	for _, r := range scanResults {
		subnet := r.IP[:strings.LastIndex(r.IP, ".")] + ".0/24"
		subnetCount[subnet]++
	}

	fmt.Printf("\nResults: %d alive endpoints, top %d:\n\n", len(scanResults), outLimit)

	fmt.Print("Distribution: ")
	for subnet, count := range subnetCount {
		fmt.Printf("%s=%d ", subnet, count)
	}
	fmt.Println()

	if community {
		fmt.Printf("%-18s %-5s %-8s %-9s\n", "ENDPOINT", "PORT", "LATENCY", "COMMUNITY")
	} else {
		fmt.Printf("%-18s %-5s %-8s\n", "ENDPOINT", "PORT", "LATENCY")
	}
	fmt.Println("--------------------------------------------------")
	for i := 0; i < outLimit; i++ {
		r := &scanResults[i]
		if community {
			commMark := ""
			if r.InCommunity {
				commMark = "✓"
			}
			fmt.Printf("%-18s %-5d %-8s %-9s\n", r.IP, r.Port, r.Latency.Round(time.Millisecond), commMark)
		} else {
			fmt.Printf("%-18s %-5d %-8s\n", r.IP, r.Port, r.Latency.Round(time.Millisecond))
		}
	}

	fmt.Println()
	fmt.Println("Use the best endpoint:")
	fmt.Printf("  awarp config set --profile <name> --endpoint %s:%d\n", scanResults[0].IP, scanResults[0].Port)

	return nil
}

// ApplyBestEndpoint scans for the best WARP endpoint and updates the profile.
func ApplyBestEndpoint(profileName string, useAWG bool) error {
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("load profile %q: %w", profileName, err)
	}

	fmt.Printf("Scanning for the best endpoint for profile %q...\n\n", profileName)
	fmt.Printf("Scanning %d IPs...\n\n", len(scanSubnets)*254)

	ips := generateIPs()

	var awgCfg *config.AWGConfig
	if useAWG {
		if profile.AWG.Jc > 0 || profile.AWG.I1 != "" {
			awgCfg = &profile.AWG
		} else {
			def := config.DefaultAWG
			awgCfg = &def
		}
	}

	results := scanAliveEndpoints(ips, scanPortList, profile.PrivateKey, profile.PublicKey, nil, awgCfg)

	if len(results) == 0 && awgCfg != nil {
		fmt.Printf("AWG scan found nothing, retrying with plain WG...\n\n")
		results = scanAliveEndpoints(ips, scanPortList, profile.PrivateKey, profile.PublicKey, nil, nil)
	}

	if len(results) == 0 && profile.PublicKey != warpServerPubKeyB64 {
		fmt.Printf("No endpoints with profile key, retrying with default WARP key...\n\n")
		results = scanAliveEndpoints(ips, scanPortList, profile.PrivateKey, warpServerPubKeyB64, nil, nil)
		if len(results) > 0 {
			fmt.Printf("Default WARP key works! Your profile's public_key differs from the standard WARP key.\n")
			fmt.Printf("This means your region uses a different WARP server key.\n")
			fmt.Printf("Consider re-registering or updating public_key in your profile.\n\n")
		}
	}

	if len(results) == 0 {
		return fmt.Errorf("no responding WARP endpoints found, keeping current endpoint %s", profile.Endpoint)
	}

	best := results[0]
	endpoint := fmt.Sprintf("%s:%d", best.IP, best.Port)
	profile.Endpoint = endpoint
	if err := profile.Save(); err != nil {
		return fmt.Errorf("save profile: %w", err)
	}

	fmt.Printf("\nOptimized endpoint: %s (latency: %s)\n", endpoint, best.Latency.Round(time.Millisecond))
	return nil
}

// generateIPs generates the full IP list from all configured subnets.
func generateIPs() []string {
	var ips []string
	for _, cidr := range scanSubnets {
		_, ipnet, _ := net.ParseCIDR(cidr)
		prefix := ipnet.IP.To4()
		if prefix == nil {
			continue
		}
		for i := 1; i <= 254; i++ {
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", prefix[0], prefix[1], prefix[2], i))
		}
	}
	return ips
}

// fetchCommunityEndpoints downloads community-verified endpoint lists and returns a map of IP -> metadata.
// Tries multiple mirrors in order: raw.githubusercontent.com, jsDelivr CDN, github.com/raw.
func fetchCommunityEndpoints() map[string]communityEndpoint {
	urls := []string{
		"https://raw.githubusercontent.com/ircfspace/endpoint/main/ip.json",
		"https://cdn.jsdelivr.net/gh/ircfspace/endpoint/ip.json",
		"https://github.com/ircfspace/endpoint/raw/main/ip.json",
		"https://ircfspace.github.io/endpoint/ip.json",
		"https://raw.githubusercontent.com/ircfspace/endpoint/main/v2.json",
		"https://cdn.jsdelivr.net/gh/ircfspace/endpoint/v2.json",
		"https://github.com/ircfspace/endpoint/raw/main/v2.json",
		"https://ircfspace.github.io/endpoint/v2.json",
	}
	all := make(map[string]communityEndpoint)
	for _, url := range urls[:4] {
		list, err := fetchAndParseCommunity(url)
		if err != nil {
			continue
		}
		for _, ep := range list {
			all[ep.IP] = ep
		}
		break
	}
	for _, url := range urls[4:] {
		list, err := fetchAndParseCommunity(url)
		if err != nil {
			continue
		}
		for _, ep := range list {
			all[ep.IP] = ep
		}
		break
	}
	return all
}

// parseCommunityIPPort splits "ip:port" or "[ip]:port" into IP and port.
func parseCommunityIPPort(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	// IPv6: [2606:...]:port
	if strings.HasPrefix(s, "[") {
		closeB := strings.LastIndex(s, "]")
		if closeB < 0 {
			return "", 0, false
		}
		ip := s[1:closeB]
		portStr := ""
		if closeB+2 <= len(s) {
			portStr = s[closeB+2:]
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, false
		}
		return ip, port, true
	}
	// IPv4: ip:port
	host, portStr, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// fetchAndParseCommunity downloads and parses a community endpoint JSON file.
// Supports multiple formats used by ircfspace/endpoint and other providers.
func fetchAndParseCommunity(url string) ([]communityEndpoint, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result []communityEndpoint

	// Format 1: [{"ip":"...","port":N,"ping":X}, ...]
	var arr []communityEndpoint
	if err := json.Unmarshal(body, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}

	// Format 2: {"subnet":{"ip":{"ping":X,"port":N}}}
	var objMap map[string]map[string]struct {
		Ping float64 `json:"ping"`
		Port int     `json:"port"`
	}
	if err := json.Unmarshal(body, &objMap); err == nil {
		for _, subnet := range objMap {
			for ip, ep := range subnet {
				result = append(result, communityEndpoint{IP: ip, Port: ep.Port, Ping: ep.Ping})
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Format 3: {"ipv4":["ip:port",...], "ipv6":["[ip]:port",...]}
	var flatList struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	}
	if err := json.Unmarshal(body, &flatList); err == nil {
		for _, s := range flatList.IPv4 {
			if ip, port, ok := parseCommunityIPPort(s); ok {
				result = append(result, communityEndpoint{IP: ip, Port: port})
			}
		}
		for _, s := range flatList.IPv6 {
			if ip, port, ok := parseCommunityIPPort(s); ok {
				result = append(result, communityEndpoint{IP: ip, Port: port})
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Format 4: {"warp":{"ipv4":[...],"ipv6":[...]}, "masque":{"ipv4":[...],"ipv6":[...]}}
	var nested struct {
		Warp struct {
			IPv4 []string `json:"ipv4"`
			IPv6 []string `json:"ipv6"`
		} `json:"warp"`
		Masque struct {
			IPv4 []string `json:"ipv4"`
			IPv6 []string `json:"ipv6"`
		} `json:"masque"`
	}
	if err := json.Unmarshal(body, &nested); err == nil {
		lists := [][]string{nested.Warp.IPv4, nested.Warp.IPv6, nested.Masque.IPv4, nested.Masque.IPv6}
		for _, list := range lists {
			for _, s := range list {
				if ip, port, ok := parseCommunityIPPort(s); ok {
					result = append(result, communityEndpoint{IP: ip, Port: port})
				}
			}
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	return nil, fmt.Errorf("unknown community JSON format")
}

func countReachable(results []ipLatency) int {
	n := 0
	for _, r := range results {
		if r.reachable {
			n++
		}
	}
	return n
}

// icmpPing pings an IP using Windows ping command and returns latency
func icmpPing(ip string) (time.Duration, bool) {
	cmd := exec.Command("cmd", "/c", "chcp 65001 >nul 2>&1 && ping -n 1 -w", strconv.Itoa(scanPingTimeout), ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, false
	}

	output := string(out)
	if strings.Contains(output, "timed out") || strings.Contains(output, "Destination host unreachable") ||
		strings.Contains(output, "превышен") || strings.Contains(output, "недоступен") {
		return 0, false
	}

	patterns := []string{
		`time[=<](\d+)ms`,
		`время[=<](\d+)мс`,
		`time[=< ](\d+)`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			ms, err := strconv.Atoi(matches[1])
			if err == nil {
				return time.Duration(ms) * time.Millisecond, true
			}
		}
	}

	return 0, false
}

// Well-known Cloudflare WARP server public key (base64-encoded, 32 bytes).
const warpServerPubKeyB64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// udpProbe sends a real WireGuard handshake initiation to check if the endpoint
// responds. If we receive any data back, the endpoint is alive.
func udpProbe(ip string, port int) bool {
	rip := net.ParseIP(ip)
	if rip == nil || rip.To4() == nil {
		return false
	}

	addr := &net.UDPAddr{IP: rip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Generate an ephemeral key for a more convincing initiation
	pubRaw := make([]byte, 32)
	if pubB64, err := func() (string, error) {
		_, pk, err := warp.GenerateKeyPair()
		return pk, err
	}(); err == nil {
		if raw, err := base64.StdEncoding.DecodeString(pubB64); err == nil && len(raw) == 32 {
			pubRaw = raw
		}
	}

	// Decode WARP server public key for MAC1 computation
	serverPub, _ := base64.StdEncoding.DecodeString(warpServerPubKeyB64)

	// Build a WireGuard handshake initiation packet (148 bytes)
	//
	// Layout (MessageInitiation in amneziawg-go):
	//   [0:4]    Type       = 1 (uint32 LE)
	//   [4:8]    Sender     = random index (uint32 LE)
	//   [8:40]   Ephemeral  = ephemeral public key (32 bytes)
	//   [40:88]  Static     = encrypted nothing (48 bytes) — zero for probe
	//   [88:116] Timestamp  = encrypted nothing (28 bytes) — zero for probe
	//   [116:132] MAC1      = computed (16 bytes)
	//   [132:148] MAC2      = zero (16 bytes)
	buf := make([]byte, 148)

	// Type (uint32 LE = 1)
	binary.LittleEndian.PutUint32(buf[0:4], 1)

	// Sender index
	var idx [4]byte
	rand.Read(idx[:])
	binary.LittleEndian.PutUint32(buf[4:8], binary.LittleEndian.Uint32(idx[:]))

	// Ephemeral public key
	copy(buf[8:40], pubRaw)

	// Compute MAC1 with the well-known WARP server key.
	// The server will either:
	//   - send a cookie reply (if under load, because MAC2 is zero)
	//   - try to process and fail (if not under load, silent drop)
	warp.ComputeMAC1(buf, serverPub)

	conn.SetWriteDeadline(time.Now().Add(scanProbeTimeout))
	if _, err := conn.Write(buf); err != nil {
		return false
	}

	// Wait for a response (cookie reply or handshake response)
	reply := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(scanProbeTimeout))
	n, err := conn.Read(reply)
	if err != nil {
		return false
	}
	return n >= 4
}

// udpProbeRegistered uses a registered WARP keypair to send a proper Noise-IK
// handshake initiation. The server only responds if it recognizes the client key.
func udpProbeRegistered(ip string, port int, clientPrivB64, serverPubB64 string) bool {
	rip := net.ParseIP(ip)
	if rip == nil || rip.To4() == nil {
		return false
	}

	msg, err := warp.BuildInitiation(clientPrivB64, serverPubB64)
	if err != nil {
		return false
	}

	addr := &net.UDPAddr{IP: rip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(scanProbeTimeout))
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	reply := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(scanProbeTimeout))
	n, err := conn.Read(reply)
	if err != nil {
		return false
	}
	return n >= 4
}

// udpProbeAWG sends warp-plus junk noise + plain WireGuard handshake initiation.
// The junk packets (20-50 random, 80-150ms apart) confuse DPI before the real
// handshake. This is the approach used by warp-plus and works where plain WG
// is blocked by DPI (Iran, UAE, etc.).
func udpProbeAWG(ip string, port int, clientPrivB64, serverPubB64 string, awgCfg config.AWGConfig) bool {
	rip := net.ParseIP(ip)
	if rip == nil || rip.To4() == nil {
		return false
	}
	wgInit, err := warp.BuildInitiation(clientPrivB64, serverPubB64)
	if err != nil {
		return false
	}
	pkts := warp.BuildJunkPackets(wgInit, awgCfg.S2)
	addr := &net.UDPAddr{IP: rip, Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	for _, pkt := range pkts.Junk {
		conn.SetWriteDeadline(time.Now().Add(scanProbeTimeout))
		if _, err := conn.Write(pkt); err != nil {
			return false
		}
		time.Sleep(time.Duration(80+randInt(0, 70)) * time.Millisecond)
	}
	conn.SetWriteDeadline(time.Now().Add(scanProbeTimeout))
	if _, err := conn.Write(pkts.Payload); err != nil {
		return false
	}
	deadline := time.Now().Add(scanProbeTimeout)
	for time.Now().Before(deadline) {
		reply := make([]byte, 1500)
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(reply)
		if err != nil {
			return false
		}
		if warp.IsValidWGResponse(reply[:n]) {
			return true
		}
	}
	return false
}

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}
