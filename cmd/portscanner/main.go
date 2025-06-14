//go:build linux
// +build linux

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"container/list"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/j-keck/arping"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// BATCH_SIZE is the number of packets to send in a single syscall.
	// This is a trade-off between syscall overhead and packet send latency.
	// A larger batch size will result in higher throughput, but also higher
	// latency.
	BATCH_SIZE = 4096
)

func main() {
	var (
		ifaceName    string
		ipsArg       string
		portsArg     string
		srcPort      int
		verbose      bool
		retryTimeout time.Duration
		maxRetries   int
		showClosed   bool
		ringSize     int
	)

	flag.StringVar(&ifaceName, "iface", "", "Network interface to use (mandatory)")
	flag.StringVar(&ipsArg, "ips", "", "Comma separated list of target IPv4 addresses")
	flag.StringVar(&portsArg, "ports", "1-1024", "Ports to scan, e.g. 80,443,1000-2000")
	flag.IntVar(&srcPort, "srcport", 54321, "Source TCP port to use for SYN packets")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.DurationVar(&retryTimeout, "retry-timeout", 1*time.Second, "Time to wait for a response before retrying a port")
	flag.IntVar(&maxRetries, "retries", 3, "Number of retries for each port before marking as filtered")
	flag.BoolVar(&showClosed, "show-closed", false, "Show closed ports in output")
	flag.IntVar(&ringSize, "ring-size", 4096, "AF_XDP ring size (descs). Increase for higher throughput. Requires more locked memory.")
	flag.Parse()

	if ifaceName == "" || ipsArg == "" || portsArg == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Parse IPs
	ips, err := parseIPsAndCIDRs(ipsArg)
	if err != nil {
		log.Fatalf("could not parse 'ips' argument: %v", err)
	}

	// Parse ports
	ports, err := parsePorts(portsArg)
	if err != nil {
		log.Fatalf("parse ports: %v", err)
	}

	// Build destination combinations
	var dests []*dest
	for _, ip := range ips {
		for _, p := range ports {
			dests = append(dests, &dest{ip: ip, port: p, status: "unknown"})
		}
	}

	// Get link info
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("netlink.LinkByName: %v", err)
	}

	// Fetch interface MAC and first IPv4 addr
	ifAddrs, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("InterfaceByName: %v", err)
	}
	srcMAC := ifAddrs.HardwareAddr
	var srcIP net.IP
	addrs, _ := ifAddrs.Addrs()
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			srcIP = ipNet.IP.To4()
			break
		}
	}
	if srcIP == nil {
		log.Fatalf("no IPv4 address found on %s", ifaceName)
	}

	// Find default gateway by parsing /proc/net/route, as it's more robust.
	defaultRoutes, err := getDefaultRoutes(verbose)
	if err != nil {
		log.Fatalf("could not determine default gateway: %v", err)
	}

	var gatewayIP net.IP
	for _, r := range defaultRoutes {
		if r.ifaceName == ifaceName {
			gatewayIP = r.gatewayIP
			break
		}
	}

	if gatewayIP == nil {
		var suggestions []string
		for _, r := range defaultRoutes {
			suggestions = append(suggestions, fmt.Sprintf("iface %s (gateway %s)", r.ifaceName, r.gatewayIP))
		}
		log.Fatalf("could not determine default gateway on %s. Found default route(s) on other interfaces: [%s]. Please specify the correct interface with -iface.", ifaceName, strings.Join(suggestions, ", "))
	}

	log.Printf("Found default gateway: %s", gatewayIP)

	gatewayMAC, err := getGatewayMAC(ifaceName, srcIP, gatewayIP, verbose)
	if err != nil {
		log.Fatalf("Could not resolve gateway MAC: %v. Please ensure you are running with sufficient privileges and you can ping the gateway.", err)
	}
	log.Printf("Resolved gateway MAC: %s", gatewayMAC)

	// Hardware checksum offloading has been disabled by user request.
	// The scanner will now calculate checksums in software.

	// done channel for graceful shutdown
	done := make(chan struct{})
	var closeOnce sync.Once

	// Set SKB mode
	xdp.DefaultXdpFlags = unix.XDP_FLAGS_SKB_MODE

	// Load the eBPF program from the object file.
	// Note: The file path is relative to the running binary.
	// We are now in cmd/portscanner, so we look in the bpf subdir.
	prog, err := xdp.LoadProgram("bpf/xdp_filter.o", "xdp_port_filter", "qidconf_map", "xsks_map")
	if err != nil {
		log.Fatalf("could not load XDP program: %v. \nHave you compiled it with `make` in `cmd/portscanner/bpf/`?", err)
	}
	log.Printf("Loaded XDP program from bpf/xdp_filter.o")
	log.Println("====================================================================================")
	log.Printf("!! IMPORTANT: The BPF program filters for incoming packets on a specific port.")
	log.Printf("!! This port MUST match the -srcport flag (current: %d).", srcPort)
	log.Printf("!! Check FILTER_PORT in 'bpf/xdp_filter.c' and recompile if necessary.")
	log.Println("====================================================================================")

	if err := prog.Attach(iface.Attrs().Index); err != nil {
		log.Fatalf("Attach program: %v", err)
	}

	// With large numbers of ports, we need larger rings. Note that this
	// may require raising the locked memory limit on your system (ulimit -l).
	socketOptions := xdp.SocketOptions{
		NumFrames:              ringSize * 2,
		FrameSize:              4096,
		FillRingNumDescs:       ringSize,
		CompletionRingNumDescs: ringSize,
		RxRingNumDescs:         ringSize,
		TxRingNumDescs:         ringSize,
	}

	xsk, err := xdp.NewSocket(iface.Attrs().Index, 0, &socketOptions)
	if err != nil {
		log.Fatalf("NewSocket: %v", err)
	}

	cleanup := func() {
		log.Println("Detaching XDP program and closing resources...")
		// Use sync.Once to ensure the socket is closed exactly once.
		closeOnce.Do(func() {
			xsk.Close()
		})

		// Detach the XDP program by running `ip link` commands. This is often more
		// reliable than library calls, especially when using SKB_MODE.
		cmd := exec.Command("ip", "link", "set", "dev", ifaceName, "xdp", "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: could not run '%s': %v. Output: %s", cmd.String(), err, string(out))
		}
		cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "xdpgeneric", "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: could not run '%s': %v. Output: %s", cmd.String(), err, string(out))
		}
	}

	var shutdownWg sync.WaitGroup
	shutdownWg.Add(1)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		select {
		case <-c:
			close(done)
		case <-done:
		}
	}()

	go func() {
		defer shutdownWg.Done()
		<-done
		cleanup()
	}()

	if err := prog.Register(0, xsk.FD()); err != nil {
		log.Fatalf("Register socket in program: %v", err)
	}

	// Enable kernel busy polling on this socket (microseconds) and prefer busy poll
	const busyPollTime = 50 // 50 usec; tune as needed
	if err := unix.SetsockoptInt(xsk.FD(), unix.SOL_SOCKET, unix.SO_BUSY_POLL, busyPollTime); err != nil {
		log.Printf("SO_BUSY_POLL set failed (kernel <3.11 or unsupported): %v", err)
	}
	if err := unix.SetsockoptInt(xsk.FD(), unix.SOL_SOCKET, unix.SO_PREFER_BUSY_POLL, 1); err != nil {
		log.Printf("SO_PREFER_BUSY_POLL set failed: %v", err)
	}

	rand.Seed(time.Now().UnixNano())

	// Randomize scan order to be less predictable and nicer to networks
	rand.Shuffle(len(dests), func(i, j int) {
		dests[i], dests[j] = dests[j], dests[i]
	})

	log.Printf("Starting SYN scan to %d combinations (%d IPs × %d ports) via %s", len(dests), len(ips), len(ports), ifaceName)

	// Map to quickly find dest by ip:port string
	outstanding := make(map[destKey]*dest, len(dests))
	var outstandingMu sync.RWMutex
	// Time-ordered list for efficient timeout handling.
	timeoutQueue := list.New()
	for _, d := range dests {
		key := makeDestKey(d.ip, d.port)
		d.key = key
		outstanding[key] = d
		d.isQueued = true // It is now in the pending queue
	}

	// Stats tracking
	var totalTx, totalRx, completedCount, openCount, closedCount, rawPacketCount uint64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastTx, lastRx, lastCompleted uint64
		lastTime := time.Now()
		ticker := time.NewTicker(2 * time.Second) // Report every 2s for less noise
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				elapsed := now.Sub(lastTime)
				if elapsed == 0 {
					continue
				}

				currentTx := atomic.LoadUint64(&totalTx)
				currentRx := atomic.LoadUint64(&totalRx)
				rawRx := atomic.LoadUint64(&rawPacketCount)
				currentCompleted := atomic.LoadUint64(&completedCount)
				currentOpen := atomic.LoadUint64(&openCount)
				currentClosed := atomic.LoadUint64(&closedCount)

				txPps := float64(currentTx-lastTx) / elapsed.Seconds()
				rxPps := float64(currentRx-lastRx) / elapsed.Seconds()
				scansPerSec := float64(currentCompleted-lastCompleted) / elapsed.Seconds()

				outstandingMu.RLock()
				outstandingCount := len(outstanding)
				outstandingMu.RUnlock()

				log.Printf("Stats: TX %.0f pps, RX %.0f pps (Raw: %d), Scans %.0f/s | Outstanding: %d | Open: %d, Closed: %d",
					txPps, rxPps, rawRx, scansPerSec, outstandingCount, currentOpen, currentClosed)

				lastTx = currentTx
				lastRx = currentRx
				lastCompleted = currentCompleted
				lastTime = now
			case <-done:
				return
			}
		}
	}()

	// Pre-fill RX descriptors
	fillDescs := xsk.GetDescs(cap(xsk.GetDescs(0, true)), true)
	if len(fillDescs) > 0 {
		xsk.Fill(fillDescs)
	}

	runtime.LockOSThread() // dedicate scanning loop to this core

	nextDestIndex := 0
	var retryDests []*dest
	var retryNextIndex int
	// Buffered channel for results to decouple printing from the receiver loop.
	resultsChan := make(chan string, 4096)
	var printerWg sync.WaitGroup
	printerWg.Add(1)
	go func() {
		defer printerWg.Done()
		for result := range resultsChan {
			fmt.Println(result)
		}
	}()

	// Create the packet packer
	packer, err := newSynPacker(srcMAC, gatewayMAC, srcIP, srcPort)
	if err != nil {
		log.Fatalf("failed to create syn packet generator: %v", err)
	}

	// Start a separate goroutine to handle timeouts and retries.
	var timeoutWg sync.WaitGroup
	timeoutWg.Add(1)
	go func() {
		defer timeoutWg.Done()
		for {
			select {
			case <-done:
				return
			default:
				outstandingMu.Lock()
				// Check the front of the queue without removing.
				front := timeoutQueue.Front()
				if front == nil {
					// Queue is empty, wait for a bit.
					outstandingMu.Unlock()
					time.Sleep(10 * time.Millisecond)
					continue
				}

				target := front.Value.(*dest)
				if time.Since(target.lastSent) < retryTimeout {
					// Head of the queue hasn't timed out, so nothing else has either.
					outstandingMu.Unlock()
					// Sleep until the head is expected to time out.
					sleepTime := retryTimeout - time.Since(target.lastSent)
					time.Sleep(sleepTime)
					continue
				}

				// The head has timed out. Process it and any others that have also timed out.
				timeoutQueue.Remove(front)
				if target.retries >= maxRetries {
					if verbose {
						resultsChan <- fmt.Sprintf("[DEBUG] Filtered: %s:%d", target.ip, target.port)
					}
					target.status = "filtered"
					delete(outstanding, target.key)
					atomic.AddUint64(&completedCount, 1)
				} else {
					if !target.isQueued {
						retryDests = append(retryDests, target)
						target.isQueued = true
					}
				}
				outstandingMu.Unlock()
			}
		}
	}()

	// Decouple receiver logic into its own goroutine to allow the sender to
	// run at full speed without being blocked by receive logic.
	var receiverWg sync.WaitGroup
	receiverWg.Add(1)
	go func() {
		defer receiverWg.Done()
		runtime.LockOSThread() // Dedicate a core to receiving

		for {
			select {
			case <-done:
				return
			default:
			}

			// Poll with a timeout to remain responsive to the 'done' channel.
			numRx, _, err := xsk.Poll(100) // 100ms timeout
			if err != nil {
				if err == unix.EAGAIN || err == unix.EINTR {
					continue // Expected on timeout
				}
				if err == unix.EBADF {
					return // Socket closed
				}
				log.Printf("Receiver poll error: %v", err)
				continue
			}

			if numRx > 0 {
				atomic.AddUint64(&rawPacketCount, uint64(numRx))
				rxDescs := xsk.Receive(numRx)
				processedPackets := 0
				for _, d := range rxDescs {
					frame := xsk.GetFrame(d)
					if ip, port, status := processPacket(frame, srcPort, verbose); status != "" {
						key := makeDestKey(ip, port)
						outstandingMu.Lock()
						if target, ok := outstanding[key]; ok {
							if target.status == "unknown" { // Avoid race with timeout
								target.status = status
								delete(outstanding, key)
								// Remove from timeout queue to prevent it from being marked as filtered.
								if target.timeoutElem != nil {
									timeoutQueue.Remove(target.timeoutElem)
								}

								atomic.AddUint64(&completedCount, 1)
								if status == "open" {
									atomic.AddUint64(&openCount, 1)
									resultsChan <- fmt.Sprintf("OPEN: %s:%d", target.ip, target.port)
								} else if status == "closed" {
									atomic.AddUint64(&closedCount, 1)
									if showClosed {
										resultsChan <- fmt.Sprintf("CLOSED: %s:%d", target.ip, target.port)
									}
								}
								processedPackets++
							}
						}
						outstandingMu.Unlock()
					}
				}
				atomic.AddUint64(&totalRx, uint64(processedPackets))
				xsk.Fill(rxDescs)
			}
			outstandingMu.RLock()
			outstandingCount := len(outstanding)
			outstandingMu.RUnlock()
			if outstandingCount == 0 {
				break
			}
		}
	}()

	outstandingMu.RLock()
	outstandingCount := len(outstanding)
	outstandingMu.RUnlock()

	var seq uint32
	for outstandingCount > 0 {
		// Always check for completions first, even if we can't send packets
		_, completed, err := xsk.Poll(0) // Use non-blocking poll for completions
		if err != nil && err != unix.EAGAIN {
			log.Printf("Poll error: %v", err)
		}
		if completed > 0 {
			xsk.Complete(completed)
		}

		// 1. Send packets
		numFree := xsk.NumFreeTxSlots()
		if numFree > 0 {
			descs := xsk.GetDescs(min(numFree, BATCH_SIZE), false)
			if len(descs) > 0 {
				packetsToSend := 0
				for i := range descs {
					var target *dest
					// Prioritize retries
					outstandingMu.Lock()
					if retryNextIndex < len(retryDests) {
						target = retryDests[retryNextIndex]
						retryNextIndex++
					} else if nextDestIndex < len(dests) {
						target = dests[nextDestIndex]
						nextDestIndex++
					} else {
						// No more packets to send for now
						if retryNextIndex > 0 && retryNextIndex == len(retryDests) {
							// We have processed all retries in the current batch, clear the slice for the next one
							retryDests = retryDests[:0]
							retryNextIndex = 0
						}
						outstandingMu.Unlock()
						break
					}
					outstandingMu.Unlock()

					target.isQueued = false

					// Get the XDP frame and pack the packet directly into it, avoiding a copy.
					frame := xsk.GetFrame(descs[i])
					pktLen := len(packer.template)
					packer.pack(frame[:pktLen], target.ip, target.port, seq)
					seq += 0x01000193 // FNV prime, any odd increment works

					// Set the frame length for transmission
					descs[i].Len = uint32(pktLen)

					target.lastSent = time.Now()
					outstandingMu.Lock()
					target.timeoutElem = timeoutQueue.PushBack(target)
					outstandingMu.Unlock()
					target.retries++
					packetsToSend++
				}

				if packetsToSend > 0 {
					xsk.Transmit(descs[:packetsToSend])
					// The non-blocking poll at the top of the loop is enough to kick the
					// kernel to start processing packets. A blocking poll here would
					// stall the send loop and starve the completion ring.
					atomic.AddUint64(&totalTx, uint64(packetsToSend))
				}
			}
		}

		// Let the sender loop yield to the OS scheduler briefly if it's running too hot
		// and not finding free slots. This can prevent live-locking on the CPU.
		if numFree == 0 {
			runtime.Gosched()
		}

		outstandingMu.RLock()
		outstandingCount = len(outstanding)
		outstandingMu.RUnlock()
	}
	runtime.UnlockOSThread()

	log.Printf("Scan complete. %d ports processed. Total packets transmitted: %d.", atomic.LoadUint64(&completedCount), atomic.LoadUint64(&totalTx))
	close(done)

	// Wait for all worker goroutines to finish before cleaning up.
	wg.Wait()
	timeoutWg.Wait()
	receiverWg.Wait()

	// Now that all goroutines are done, we can close the results channel and wait for the printer.
	close(resultsChan)
	printerWg.Wait()

	// Finally, wait for the shutdown/cleanup goroutine.
	shutdownWg.Wait()
	log.Println("Cleanup complete.")
}

func parseIPsAndCIDRs(s string) ([]net.IP, error) {
	var ips []net.IP
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "/") {
			// CIDR
			_, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			if ipnet.IP.To4() == nil {
				return nil, fmt.Errorf("only IPv4 CIDRs are supported: %q", part)
			}

			// Iterate over all IPs in the network. For subnets larger than /31,
			// skip the network and broadcast addresses as they are not scannable.
			maskSize, bits := ipnet.Mask.Size()
			isRegularSubnet := bits == 32 && maskSize < 31

			startIP := ipnet.IP.Mask(ipnet.Mask)
			if isRegularSubnet {
				inc(startIP) // Skip network address
			}

			for ip := startIP; ipnet.Contains(ip); inc(ip) {
				addr := make(net.IP, len(ip))
				copy(addr, ip)

				// For regular subnets, check if we're at the broadcast address and stop.
				if isRegularSubnet {
					// The broadcast address is the last address in the range. If the next
					// IP is not in the subnet, the current one is the broadcast address.
					nextIP := make(net.IP, len(ip))
					copy(nextIP, ip)
					inc(nextIP)
					if !ipnet.Contains(nextIP) {
						break // Don't include broadcast address
					}
				}
				ips = append(ips, addr.To4())
			}
		} else {
			// Single IP
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %q", part)
			}
			ip = ip.To4()
			if ip == nil {
				return nil, fmt.Errorf("only IPv4 addresses are supported: %q", part)
			}
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid IPs or CIDRs found")
	}
	return ips, nil
}

// inc increments an IP address. It is used to iterate over a CIDR range.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type destKey [18]byte // 16 for IP, 2 for port

func makeDestKey(ip net.IP, port uint16) destKey {
	var key destKey
	copy(key[:16], ip.To16())
	binary.BigEndian.PutUint16(key[16:], port)
	return key
}

type dest struct {
	key         destKey
	ip          net.IP
	port        uint16
	status      string // unknown, open, closed, filtered
	retries     int
	lastSent    time.Time
	isQueued    bool
	timeoutElem *list.Element
}

func parsePorts(s string) ([]uint16, error) {
	var res []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			var start, end int
			if _, err := fmt.Sscanf(part, "%d-%d", &start, &end); err != nil {
				return nil, fmt.Errorf("invalid port range %s", part)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %s", part)
			}
			for p := start; p <= end; p++ {
				res = append(res, uint16(p))
			}
		} else {
			var p int
			if _, err := fmt.Sscanf(part, "%d", &p); err != nil {
				return nil, fmt.Errorf("invalid port %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			res = append(res, uint16(p))
		}
	}
	return res, nil
}

// processPacket inspects packet, returns target key if SYN-ACK observed
func processPacket(pkt []byte, srcPort int, verbose bool) (ip net.IP, port uint16, status string) {
	if len(pkt) < 34 { // Ethernet + IPv4 min
		return
	}
	if pkt[12] != 0x08 || pkt[13] != 0x00 { // not IPv4
		return
	}
	ipHeaderLen := (pkt[14] & 0x0F) * 4
	if len(pkt) < int(14+ipHeaderLen+20) {
		return
	}
	proto := pkt[23]
	if proto != 6 { // TCP
		return
	}
	tcpStart := 14 + ipHeaderLen
	srcPortPkt := int(pkt[tcpStart])<<8 | int(pkt[tcpStart+1])
	dstPortPkt := int(pkt[tcpStart+2])<<8 | int(pkt[tcpStart+3])
	if dstPortPkt != srcPort { // only care replies to our src port
		return
	}
	flags := pkt[tcpStart+13]
	srcIP := net.IPv4(pkt[26], pkt[27], pkt[28], pkt[29])

	if flags&0x12 == 0x12 { // SYN+ACK
		return srcIP, uint16(srcPortPkt), "open"
	}
	if flags&0x14 == 0x14 || flags&0x04 == 0x04 { // RST+ACK or RST
		return srcIP, uint16(srcPortPkt), "closed"
	}
	if verbose {
		// log non-SYN ACK responses for debugging
		fmt.Printf("DEBUG reply flags %02x from %s:%d\n", flags, srcIP.String(), srcPortPkt)
	}
	return
}

// getMACFromCache reads the system's ARP table to find the MAC address for a given IP.
// This is much faster than sending an ARP request.
func getMACFromCache(ifaceName string, ip net.IP, verbose bool) (net.HardwareAddr, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// Line format: IP address, HW type, Flags, HW address, Mask, Device
		if fields[0] == ip.String() && fields[5] == ifaceName {
			// Check if the entry is complete (flag 0x2)
			if fields[2] == "0x2" {
				mac, err := net.ParseMAC(fields[3])
				if err == nil {
					return mac, nil
				}
				if verbose {
					log.Printf("Invalid MAC '%s' in ARP cache for IP %s", fields[3], ip)
				}
			}
		}
	}
	return nil, scanner.Err() // Not found or scanner error
}

func getGatewayMAC(ifaceName string, srcIP, gatewayIP net.IP, verbose bool) (net.HardwareAddr, error) {
	// 1. Try to read from ARP cache first for a significant speedup.
	mac, err := getMACFromCache(ifaceName, gatewayIP, verbose)
	if err != nil && verbose {
		log.Printf("Could not read from ARP cache: %v. Will send ARP request.", err)
	}
	if mac != nil {
		if verbose {
			log.Printf("Resolved gateway MAC from cache: %s", mac)
		}
		return mac, nil
	}

	if verbose {
		log.Println("Gateway MAC not in cache, sending ARP request.")
	}

	// The arping library provides a more robust way to send ARP requests and get replies.
	// It handles the raw socket creation and packet parsing for us.
	mac, _, err = arping.Ping(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("arping failed: %w", err)
	}
	return mac, nil
}

type defaultRouteInfo struct {
	ifaceName string
	gatewayIP net.IP
}

// getDefaultRoutes reads /proc/net/route to find the default gateway(s).
func getDefaultRoutes(verbose bool) ([]defaultRouteInfo, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var routes []defaultRouteInfo

	scanner := bufio.NewScanner(f)
	// Skip header
	if scanner.Scan() {
		// Do nothing with the header line
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if verbose {
			log.Printf("Parsing route: %s", line)
		}
		// Default route is where destination and mask are both 0.
		if fields[1] == "00000000" && fields[7] == "00000000" {
			gatewayHex := fields[2]
			var gw uint32
			_, err := fmt.Sscanf(gatewayHex, "%x", &gw)
			if err != nil {
				if verbose {
					log.Printf("Could not parse gateway hex '%s': %v", gatewayHex, err)
				}
				continue // Couldn't parse gateway address
			}

			// The gateway address in /proc/net/route is in little-endian format.
			gatewayIP := make(net.IP, 4)
			binary.LittleEndian.PutUint32(gatewayIP, gw)

			routes = append(routes, defaultRouteInfo{
				ifaceName: fields[0],
				gatewayIP: gatewayIP,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning /proc/net/route: %w", err)
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no default route found in /proc/net/route")
	}

	return routes, nil
}

// synPacker is used to quickly craft SYN packets by creating a template and
// only modifying the necessary fields for each new packet.
type synPacker struct {
	template          []byte
	ethHeaderLen      int
	ipHeaderLen       int
	ipDstOffset       int
	tcpDstPortOffset  int
	tcpSeqOffset      int
	ipChecksumOffset  int
	tcpChecksumOffset int
	pseudoHeader      []byte
}

func newSynPacker(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, srcPort int) (*synPacker, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    net.IP{127, 0, 0, 1}, // Placeholder
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(80), // Placeholder
		Seq:     12345,              // Placeholder
		SYN:     true,
		Window:  1024,
	}
	// DstIP in ip is a placeholder, but for checksum calculation it's fine.
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return nil, fmt.Errorf("serialize template packet: %w", err)
	}

	packetBytes := buf.Bytes()
	decodedPacket := gopacket.NewPacket(packetBytes, layers.LayerTypeEthernet, gopacket.NoCopy)
	ipLayer := decodedPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpLayer := decodedPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)

	ethHeaderLen := len(decodedPacket.Layer(layers.LayerTypeEthernet).LayerContents())
	ipHeaderLen := int(ipLayer.IHL * 4)

	// Manually construct the pseudo-header for checksum calculation, as
	// gopacket does not expose this directly.
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipLayer.SrcIP.To4())
	copy(pseudoHeader[4:8], ipLayer.DstIP.To4()) // DstIP is a placeholder
	pseudoHeader[8] = 0                          // Reserved
	pseudoHeader[9] = byte(layers.IPProtocolTCP)
	tcpLen := uint16(len(tcpLayer.Contents) + len(tcpLayer.Payload))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)

	p := &synPacker{
		template:          packetBytes,
		ethHeaderLen:      ethHeaderLen,
		ipHeaderLen:       ipHeaderLen,
		ipDstOffset:       ethHeaderLen + 16,               // DstIP is at byte 16 of IP header
		tcpDstPortOffset:  ethHeaderLen + ipHeaderLen + 2,  // DstPort is at byte 2 of TCP header
		tcpSeqOffset:      ethHeaderLen + ipHeaderLen + 4,  // Seq is at byte 4
		ipChecksumOffset:  ethHeaderLen + 10,               // Checksum is at byte 10 of IP header
		tcpChecksumOffset: ethHeaderLen + ipHeaderLen + 16, // Checksum is at byte 16 of TCP header
		pseudoHeader:      pseudoHeader,
	}

	return p, nil
}

// pack quickly constructs a packet by modifying the template.
// It performs checksum calculation in software to avoid issues with
// hardware offloading, which can be unreliable.
func (p *synPacker) pack(pktBuf []byte, dstIP net.IP, dstPort uint16, seq uint32) {
	copy(pktBuf, p.template)

	// Update headers
	copy(pktBuf[p.ipDstOffset:p.ipDstOffset+4], dstIP.To4())
	binary.BigEndian.PutUint16(pktBuf[p.tcpDstPortOffset:p.tcpDstPortOffset+2], dstPort)
	binary.BigEndian.PutUint32(pktBuf[p.tcpSeqOffset:p.tcpSeqOffset+4], seq)

	// Zero out checksums for recalculation.
	binary.BigEndian.PutUint16(pktBuf[p.ipChecksumOffset:p.ipChecksumOffset+2], 0)
	binary.BigEndian.PutUint16(pktBuf[p.tcpChecksumOffset:p.tcpChecksumOffset+2], 0)

	// Software checksum calculation
	// Recalculate IP checksum
	ipHeader := pktBuf[p.ethHeaderLen : p.ethHeaderLen+p.ipHeaderLen]
	ipCsum := checksum(ipHeader)
	binary.BigEndian.PutUint16(pktBuf[p.ipChecksumOffset:p.ipChecksumOffset+2], ipCsum)

	// Recalculate TCP checksum
	copy(p.pseudoHeader[4:8], dstIP.To4()) // DstIP is part of pseudo-header
	tcpSegment := pktBuf[p.ethHeaderLen+p.ipHeaderLen:]
	tcpCsum := tcpChecksum(p.pseudoHeader, tcpSegment)
	binary.BigEndian.PutUint16(pktBuf[p.tcpChecksumOffset:p.tcpChecksumOffset+2], tcpCsum)
}

// checksum calculates the IP checksum.
func checksum(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(binary.BigEndian.Uint16(buf[:2]))
	}
	if len(buf) == 1 {
		sum += uint32(buf[0]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// tcpPseudoHeaderChecksum calculates only the checksum of the TCP pseudo-header.
// This is used with checksum offloading.
func tcpPseudoHeaderChecksum(pseudoHeader []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(pseudoHeader)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i:]))
	}
	for sum>>16 > 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// tcpChecksum calculates the TCP checksum.
func tcpChecksum(pseudoHeader, tcpSegment []byte) uint16 {
	sum := uint32(0)

	// Pseudo-header
	for i := 0; i < len(pseudoHeader)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i:]))
	}

	// TCP segment
	for i := 0; i < len(tcpSegment)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSegment[i:]))
	}
	if len(tcpSegment)%2 == 1 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	for sum>>16 > 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkAndEnableChecksumOffloading(ifaceName string, verbose bool) bool {
	ethtoolPath, err := exec.LookPath("ethtool")
	if err != nil {
		log.Println("Warning: 'ethtool' not found. Cannot verify or enable checksum offloading.")
		log.Println("Falling back to software checksums, which may impact performance.")
		return false
	}

	// isOffloadEnabled checks the current state of TX checksumming.
	isOffloadEnabled := func() bool {
		cmd := exec.Command(ethtoolPath, "-k", ifaceName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if verbose {
				log.Printf("Could not check offloading features with 'ethtool -k': %v", err)
			}
			return false // Assume disabled if we can't check
		}
		// Modern ethtool uses 'tx-checksum-ip-generic', older might show 'tx-checksumming'.
		// We look for either being 'on'.
		output := string(out)
		return strings.Contains(output, "tx-checksum-ip-generic: on") || strings.Contains(output, "tx-checksumming: on")
	}

	if isOffloadEnabled() {
		log.Println("Hardware TX checksum offloading is already enabled.")
		return true
	}

	log.Println("Attempting to enable hardware TX checksum offloading for performance...")
	// Using 'tx on' is a general way to enable TCP/UDP/SCTP checksum offload on transmit.
	cmd := exec.Command(ethtoolPath, "-K", ifaceName, "tx", "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: Failed to enable TX checksum offloading with 'ethtool -K %s tx on'. Error: %v", ifaceName, err)
		if len(out) > 0 {
			log.Printf("Output: %s", string(out))
		}
		log.Println("Falling back to software checksums, which may impact performance.")
		return false
	}

	// Verify that it was enabled
	if isOffloadEnabled() {
		log.Println("Successfully enabled hardware TX checksum offloading.")
		return true
	}

	log.Println("Warning: Attempted to enable hardware TX checksum offloading, but it's still disabled.")
	log.Println("Falling back to software checksums, which may impact performance.")
	return false
}
