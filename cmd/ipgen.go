package cmd

import (
	"crypto/rand"
	"math/big"
	"net"
)

// lcg holds state for a Linear Congruential Generator over a range [0, mod).
// Guarantees full period (visits every integer exactly once) per Hull-Dobell.
type lcg struct {
	mod  uint64
	mult uint64
	inc  uint64
	cur  uint64
}

// newLCG creates an LCG with full period for given modulus.
func newLCG(mod uint64) lcg {
	var mult, inc uint64
	// Try random valid params until Hull-Dobell satisfied
	for {
		mult = 1 + randUint64(mod-1)
		inc = randUint64(mod)
		if mult%mod == 0 {
			continue
		}
		if inc == 0 || mod%inc == 0 {
			continue
		}
		break
	}
	return lcg{mod: mod, mult: mult, inc: inc, cur: randUint64(mod)}
}

func (l *lcg) next() uint64 {
	l.cur = (l.mult*l.cur + l.inc) % l.mod
	return l.cur
}

func randUint64(max uint64) uint64 {
	if max <= 1 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return uint64(n.Int64())
}

// ipGenerator yields random IPs from CIDR ranges, unbiased.
// Each batch returns one random IP per range; ranges are shuffled between cycles.
type ipGenerator struct {
	ranges []*cidrRange // copy of original ranges
	order  []int        // shuffled range indices for current cycle
	pos    int          // position in order[]
	lcgs   []lcg        // one LCG per range
}

type cidrRange struct {
	base net.IP
	mask net.IPMask
	ones int
	size uint64
}

func newIPGenerator(cidrs []string, skipNetBcast bool) *ipGenerator {
	g := &ipGenerator{order: make([]int, len(cidrs))}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		size := uint64(1) << (bits - ones)
		if skipNetBcast && ones < bits {
			size -= 2
		}
		g.ranges = append(g.ranges, &cidrRange{
			base: ipnet.IP.To4(),
			mask: ipnet.Mask,
			ones: ones,
			size: size,
		})
	}
	g.lcgs = make([]lcg, len(g.ranges))
	for i := range g.lcgs {
		g.lcgs[i] = newLCG(g.ranges[i].size)
	}
	g.shuffle()
	return g
}

// nextBatch returns one random IP per CIDR range, shuffling ranges between cycles.
func (g *ipGenerator) nextBatch() []string {
	if g.pos >= len(g.order) {
		g.shuffle()
	}
	batch := make([]string, 0, len(g.order))
	for _, idx := range g.order {
		ip := g.ipAt(idx, g.lcgs[idx].next())
		if ip != "" {
			batch = append(batch, ip)
		}
	}
	g.pos = len(g.order)
	return batch
}

// ipAt computes the nth IP in the range (n=0 → first usable host).
func (g *ipGenerator) ipAt(idx int, n uint64) string {
	r := g.ranges[idx]
	ip := make(net.IP, 4)
	copy(ip, r.base)
	// Add offset + 1 to skip network address (n=0 becomes .1)
	n++
	for i := 4 - 1; n > 0 && i >= 0; i-- {
		ip[i] += byte(n & 0xff)
		n >>= 8
	}
	// Verify it's within the subnet
	if !r.base.Mask(r.mask).Equal(ip.Mask(r.mask)) {
		return ""
	}
	return ip.String()
}

func (g *ipGenerator) shuffle() {
	// Fisher-Yates shuffle
	n := len(g.ranges)
	g.order = make([]int, n)
	for i := 0; i < n; i++ {
		j := int(randUint64(uint64(i + 1)))
		g.order[i] = g.order[j]
		g.order[j] = i
	}
	g.pos = 0
}

// len returns the total number of IPs across all ranges.
func (g *ipGenerator) len() int {
	total := 0
	for _, r := range g.ranges {
		total += int(r.size)
	}
	return total
}
