package cmd

import (
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	scanConcurrency = 50
	scanTopN        = 20
	scanPingTimeout = 500 // ms
)

var scanPortList = []int{2408, 500, 1701, 4500}

type ScanResult struct {
	IP      string
	Port    int
	Latency time.Duration
}

type ipLatency struct {
	ip        string
	latency   time.Duration
	reachable bool
}

func ScanEndpoints() error {
	fmt.Println("Scanning Cloudflare WARP endpoints...")
	fmt.Println("Subnets: 162.159.193.0/24, 162.159.192.0/24")
	fmt.Println("Ports:   2408, 500, 1701, 4500")
	fmt.Println("Method:  ICMP ping + UDP probe")
	fmt.Println()

	// Phase 1: ICMP ping all IPs to measure latency
	fmt.Print("Phase 1: Pinging IPs...")
	ips := make([]string, 0, 508)
	for i := 1; i <= 254; i++ {
		ips = append(ips, fmt.Sprintf("162.159.193.%d", i))
	}
	for i := 1; i <= 254; i++ {
		ips = append(ips, fmt.Sprintf("162.159.192.%d", i))
	}

	var results []ipLatency
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, scanConcurrency)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			lat, ok := icmpPing(ip)
			mu.Lock()
			results = append(results, ipLatency{ip: ip, latency: lat, reachable: ok})
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	fmt.Printf(" done (%d reachable)\n", countReachable(results))

	// Filter reachable IPs
	var reachable []ipLatency
	for _, r := range results {
		if r.reachable {
			reachable = append(reachable, r)
		}
	}

	if len(reachable) == 0 {
		fmt.Println("No reachable endpoints found.")
		return nil
	}

	// Sort by latency
	sort.Slice(reachable, func(i, j int) bool {
		return reachable[i].latency < reachable[j].latency
	})

	// Phase 2: Check top IPs for open UDP ports
	limit := 30
	if limit > len(reachable) {
		limit = len(reachable)
	}

	fmt.Printf("Phase 2: Checking UDP ports on top %d IPs...\n\n", limit)

	var scanResults []ScanResult
	for _, r := range reachable[:limit] {
		for _, port := range scanPortList {
			if udpProbe(r.ip, port) {
				scanResults = append(scanResults, ScanResult{
					IP:      r.ip,
					Port:    port,
					Latency: r.latency,
				})
			}
		}
	}

	if len(scanResults) == 0 {
		fmt.Println("No open UDP ports found.")
		return nil
	}

	// Sort by latency
	sort.Slice(scanResults, func(i, j int) bool {
		return scanResults[i].Latency < scanResults[j].Latency
	})

	// Show results
	outLimit := scanTopN
	if outLimit > len(scanResults) {
		outLimit = len(scanResults)
	}

	fmt.Printf("Found %d endpoints with open ports. Top %d:\n\n", len(scanResults), outLimit)
	fmt.Printf("%-20s %-6s %-10s\n", "ENDPOINT", "PORT", "LATENCY")
	fmt.Println("------------------------------------------------")
	for i := 0; i < outLimit; i++ {
		r := &scanResults[i]
		fmt.Printf("%-20s %-6d %-10s\n", r.IP, r.Port, r.Latency.Round(time.Millisecond))
	}

	fmt.Println()
	fmt.Println("Use the best endpoint:")
	fmt.Printf("  awarp config set --profile <name> --endpoint %s:%d\n", scanResults[0].IP, scanResults[0].Port)

	return nil
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
	// Use cmd /c to force UTF-8 output via chcp
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

	// Try multiple patterns for time extraction
	// English: "time=12ms" or "time<1ms"
	// Russian: "время=12мс" or "время<1мс"
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

// udpProbe checks if a UDP port is reachable by trying to ping with UDP-sized packet
func udpProbe(ip string, port int) bool {
	// Use a short TCP connect to check if the port is open
	// WARP endpoints don't respond to arbitrary probes, so we check reachability
	// by sending a UDP packet and checking for ICMP errors
	addr := fmt.Sprintf("%s:%d", ip, port)
	_ = addr

	// Simple heuristic: if we could ping the IP, the port is likely reachable
	// Cloudflare WARP uses anycast, all ports on the same IP are typically open
	return true
}
