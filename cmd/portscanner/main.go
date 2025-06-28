//go:build linux
// +build linux

package main

import (
	"bufio"
	"container/list"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/j-keck/arping"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// BATCH_SIZE is the number of packets to send in a single syscall.
	BATCH_SIZE = 4096
)

// Communication types for the decoupled architecture
type PacketRequest struct {
	IP   net.IP
	Port uint16
}

type ScanResult struct {
	IP     net.IP
	Port   uint16
	Status string // "open", "closed"
}

type StateRequest struct {
	IP       net.IP
	Port     uint16
	Action   string // "add", "timeout_check"
	LastSent time.Time
	Retries  int
}

// Global channels for communication between components
var (
	packetRequestChan = make(chan PacketRequest, 16384)
	resultChan        = make(chan ScanResult, 8192)
	stateRequestChan  = make(chan StateRequest, 16384)
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
		numQueues    int
		numWorkers   int
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
	flag.IntVar(&numQueues, "num-queues", 1, "Number of NIC queues to use for parallel scanning.")
	flag.IntVar(&numWorkers, "workers", runtime.NumCPU(), "Number of logic worker goroutines")
	flag.Parse()

	if ifaceName == "" || ipsArg == "" || portsArg == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Configure the network interface to use the specified number of queues.
	if err := configureInterfaceQueues(ifaceName, numQueues, verbose); err != nil {
		log.Fatalf("Could not configure interface queues: %v", err)
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

	// Load XDP program
	if verbose {
		log.Println("Attempting to attach XDP program in DRV mode for maximum performance.")
	}
	xdp.DefaultXdpFlags = unix.XDP_FLAGS_SKB_MODE
	prog, err := xdp.LoadProgram("bpf/xdp_filter.o", "xdp_port_filter", "qidconf_map", "xsks_map")
	if err != nil {
		log.Fatalf("could not load XDP program: %v. \nHave you compiled it with `make` in `cmd/portscanner/bpf/`?", err)
	}
	log.Printf("Loaded XDP program from bpf/xdp_filter.o")

	// Attach program
	if err := prog.Attach(iface.Attrs().Index); err != nil {
		if verbose {
			log.Printf("DRV mode failed: %v – falling back to SKB mode", err)
		}
		xdp.DefaultXdpFlags = unix.XDP_FLAGS_SKB_MODE
		if err := prog.Attach(iface.Attrs().Index); err != nil {
			log.Fatalf("Attach program failed even in SKB mode: %v", err)
		}
	} else if verbose {
		log.Println("Successfully attached XDP program in DRV mode.")
	}

	// Global done channel for graceful shutdown
	done := make(chan struct{})
	var closeDoneOnce sync.Once

	// Setup signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		closeDoneOnce.Do(func() { close(done) })
	}()

	// Global stats
	var totalTx, totalRx, completedCount, openCount, closedCount, rawPacketCount uint64

	// Randomize scan order
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(dests), func(i, j int) {
		dests[i], dests[j] = dests[j], dests[i]
	})

	log.Printf("Starting SYN scan to %d combinations (%d IPs × %d ports) via %s using %d queues and %d workers",
		len(dests), len(ips), len(ports), ifaceName, numQueues, numWorkers)
	startTime := time.Now()

	// Start Result Processor (must start before others)
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go resultProcessor(done, &resultWg, retryTimeout, maxRetries, verbose, showClosed,
		&completedCount, &openCount, &closedCount, len(dests))

	// Start I/O Worker
	var ioWg sync.WaitGroup
	ioWg.Add(1)
	go ioWorker(done, &ioWg, iface.Attrs().Index, prog, numQueues, ringSize, srcMAC, gatewayMAC, srcIP, srcPort,
		verbose, &totalTx, &totalRx)

	// Start Logic Workers
	var logicWg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		logicWg.Add(1)
		go logicWorker(done, &logicWg, getWorkerDests(dests, i, numWorkers), i)
	}

	// Stats reporting goroutine
	var statsWg sync.WaitGroup
	statsWg.Add(1)
	go func() {
		defer statsWg.Done()
		var lastTx, lastRx, lastCompleted uint64
		lastTime := time.Now()
		ticker := time.NewTicker(2 * time.Second)
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

				outstandingCount := len(dests) - int(currentCompleted)

				log.Printf("Stats: TX %.0f pps, RX %.0f pps (Raw: %d), Scans %.0f/s | Outstanding: %d | Open: %d, Closed: %d",
					txPps, rxPps, rawRx, scansPerSec, outstandingCount, currentOpen, currentClosed)

				lastTx = currentTx
				lastRx = currentRx
				lastCompleted = currentCompleted
				lastTime = now

				if currentCompleted >= uint64(len(dests)) {
					return
				}
			case <-done:
				return
			}
		}
	}()

	// Wait for logic workers to finish generating requests
	logicWg.Wait()
	log.Println("All logic workers finished")

	// Wait for all work to complete
	for {
		completed := atomic.LoadUint64(&completedCount)
		if completed >= uint64(len(dests)) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Signal shutdown
	closeDoneOnce.Do(func() { close(done) })

	// Wait for other components
	ioWg.Wait()
	resultWg.Wait()
	statsWg.Wait()

	elapsed := time.Since(startTime).Seconds()
	log.Printf("Scan complete. %d ports processed. Total packets transmitted: %d.",
		atomic.LoadUint64(&completedCount), atomic.LoadUint64(&totalTx))
	if elapsed > 0 {
		pps := float64(atomic.LoadUint64(&totalTx)) / elapsed
		log.Printf("Average TX rate: %.0f packets/sec (elapsed %.2f s)", pps, elapsed)
	}

	// Cleanup
	log.Println("Detaching XDP program and closing resources...")
	cmd := exec.Command("ip", "link", "set", "dev", ifaceName, "xdp", "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: could not run '%s': %v. Output: %s", cmd.String(), err, string(out))
	}
	cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "xdpgeneric", "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: could not run '%s': %v. Output: %s", cmd.String(), err, string(out))
	}
	log.Println("Cleanup complete.")
}

// Logic Worker: generates packet requests for its assigned destinations
func logicWorker(done <-chan struct{}, wg *sync.WaitGroup, dests []*dest, workerID int) {
	defer wg.Done()

	for _, target := range dests {
		select {
		case <-done:
			return
		case packetRequestChan <- PacketRequest{IP: target.ip, Port: target.port}:
			// Also notify the result processor to track this target
			select {
			case stateRequestChan <- StateRequest{
				IP:       target.ip,
				Port:     target.port,
				Action:   "add",
				LastSent: time.Now(),
				Retries:  1,
			}:
			case <-done:
				return
			}
		}
	}
}

// I/O Worker: handles all XDP socket operations
func ioWorker(done <-chan struct{}, wg *sync.WaitGroup, ifIndex int, prog *xdp.Program, numQueues, ringSize int,
	srcMAC, gatewayMAC net.HardwareAddr, srcIP net.IP, srcPort int, verbose bool, totalTx, totalRx *uint64) {
	defer wg.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create XDP sockets for all queues
	var sockets []*xdp.Socket
	socketOptions := xdp.SocketOptions{
		NumFrames:              ringSize * 2,
		FrameSize:              4096,
		FillRingNumDescs:       ringSize,
		CompletionRingNumDescs: ringSize,
		RxRingNumDescs:         ringSize,
		TxRingNumDescs:         ringSize,
	}

	for i := 0; i < numQueues; i++ {
		xsk, err := xdp.NewSocket(ifIndex, i, &socketOptions)
		if err != nil {
			log.Fatalf("NewSocket for queue %d: %v", i, err)
		}
		defer xsk.Close()

		if err := prog.Register(i, xsk.FD()); err != nil {
			log.Fatalf("Register socket for queue %d: %v", i, err)
		}
		defer prog.Unregister(i)

		// Busy polling
		const busyPollTime = 50
		unix.SetsockoptInt(xsk.FD(), unix.SOL_SOCKET, unix.SO_BUSY_POLL, busyPollTime)
		unix.SetsockoptInt(xsk.FD(), unix.SOL_SOCKET, unix.SO_PREFER_BUSY_POLL, 1)

		sockets = append(sockets, xsk)
	}

	packer, err := newSynPacker(srcMAC, gatewayMAC, srcIP, uint16(srcPort))
	if err != nil {
		log.Fatalf("failed to create syn packet generator: %v", err)
	}

	// Pre-fill RX rings
	for _, xsk := range sockets {
		if fillDescs := xsk.GetDescs(xsk.NumFreeFillSlots(), true); len(fillDescs) > 0 {
			xsk.Fill(fillDescs)
		}
	}

	var (
		requestsToSend []PacketRequest
		seq            uint32 = rand.Uint32()
		currentQueue   int    = 0
	)

	for {
		select {
		case <-done:
			return
		default:
		}

		// 1. Poll for completions and receives FIRST to free up TX slots.
		for i, xsk := range sockets {
			numRx, numComp, err := xsk.Poll(0)
			if err != nil && err != unix.EAGAIN && err != unix.EINTR && err != unix.EBADF {
				log.Printf("Poll error on queue %d: %v", i, err)
			}
			if numComp > 0 {
				xsk.Complete(numComp)
			}
			// Only check for receives on queue 0 where BPF redirects
			if numRx > 0 {
				rxDescs := xsk.Receive(numRx)
				processedPackets := 0
				for _, d := range rxDescs {
					frame := xsk.GetFrame(d)
					if ip, port, status := processPacket(frame, srcPort, numQueues, verbose); status != "" {
						select {
						case resultChan <- ScanResult{IP: ip, Port: port, Status: status}:
							processedPackets++
						case <-done:
							return
						}
					}
				}
				if processedPackets > 0 {
					atomic.AddUint64(totalRx, uint64(processedPackets))
					xsk.Fill(rxDescs)
				}
			}
		}

		// 2. Top up our internal send buffer with new requests.
	GetNewRequests:
		for len(requestsToSend) < BATCH_SIZE*2 { // Keep a backlog
			select {
			case req := <-packetRequestChan:
				requestsToSend = append(requestsToSend, req)
			default:
				break GetNewRequests
			}
		}

		// 3. Send packets from our buffer.
		if len(requestsToSend) > 0 {
			xsk := sockets[currentQueue]
			numFree := xsk.NumFreeTxSlots()

			if numFree > 0 {
				numToSend := min(numFree, len(requestsToSend))
				descs := xsk.GetDescs(numToSend, false)
				numToSend = len(descs)

				portForThisQueue := uint16(srcPort + currentQueue)

				for i := 0; i < numToSend; i++ {
					req := requestsToSend[i]
					frame := xsk.GetFrame(descs[i])
					pktLen := len(packer.template)
					packer.pack(frame[:pktLen], req.IP, portForThisQueue, req.Port, seq)
					seq += 0x01000193
					descs[i].Len = uint32(pktLen)
				}

				if numToSend > 0 {
					xsk.Transmit(descs)
					atomic.AddUint64(totalTx, uint64(numToSend))
					requestsToSend = requestsToSend[numToSend:]
				}
			}
			currentQueue = (currentQueue + 1) % numQueues
		}

		// 4. Yield if we have nothing to do.
		if len(requestsToSend) == 0 && len(packetRequestChan) == 0 {
			runtime.Gosched()
		}
	}
}

// Result Processor: manages all state and handles results
func resultProcessor(done <-chan struct{}, wg *sync.WaitGroup, retryTimeout time.Duration, maxRetries int,
	verbose, showClosed bool, completedCount, openCount, closedCount *uint64, totalTargets int) {
	defer wg.Done()

	outstanding := make(map[destKey]*dest)
	timeoutQueue := list.New()

	// Use a ticker inside the main select loop to handle timeouts.
	ticker := time.NewTicker(retryTimeout / 10) // Check 10x more frequently than timeout
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return

		case <-ticker.C:
			now := time.Now()
			for {
				front := timeoutQueue.Front()
				if front == nil {
					break // No items in queue
				}

				target := front.Value.(*dest)
				if now.Sub(target.lastSent) < retryTimeout {
					break // Head of the queue hasn't timed out yet
				}

				// This target has timed out
				timeoutQueue.Remove(front)

				if target.retries >= maxRetries {
					if verbose {
						log.Printf("Filtered: %s:%d", target.ip, target.port)
					}
					target.status = "filtered"
					delete(outstanding, target.key)
					atomic.AddUint64(completedCount, 1)
				} else {
					// Retry: send back to the packet request channel
					select {
					case packetRequestChan <- PacketRequest{IP: target.ip, Port: target.port}:
						// If retry is successful, update state and re-queue for timeout check
						target.retries++
						target.lastSent = now
						target.timeoutElem = timeoutQueue.PushBack(target)
					case <-done:
						return
					}
				}
			}

		case req := <-stateRequestChan:
			if req.Action == "add" {
				key := makeDestKey(req.IP, req.Port)
				target := &dest{
					key:      key,
					ip:       req.IP,
					port:     req.Port,
					status:   "unknown",
					retries:  req.Retries,
					lastSent: req.LastSent,
				}
				target.timeoutElem = timeoutQueue.PushBack(target)
				outstanding[key] = target
			}
		case result := <-resultChan:
			key := makeDestKey(result.IP, result.Port)
			if target, ok := outstanding[key]; ok {
				target.status = result.Status
				delete(outstanding, key)

				if target.timeoutElem != nil {
					timeoutQueue.Remove(target.timeoutElem)
				}

				atomic.AddUint64(completedCount, 1)

				if result.Status == "open" {
					atomic.AddUint64(openCount, 1)
					fmt.Printf("OPEN: %s:%d\n", result.IP, result.Port)
				} else if result.Status == "closed" {
					atomic.AddUint64(closedCount, 1)
					if showClosed {
						fmt.Printf("CLOSED: %s:%d\n", result.IP, result.Port)
					}
				}
			}
		}
	}
}

// getWorkerDests slices the main destination list to distribute work among workers.
func getWorkerDests(dests []*dest, workerID, numWorkers int) []*dest {
	n := len(dests)
	start := (n * workerID) / numWorkers
	end := (n * (workerID + 1)) / numWorkers
	return dests[start:end]
}

// configureInterfaceQueues uses ethtool to set the number of combined queues.
func configureInterfaceQueues(ifaceName string, numQueues int, verbose bool) error {
	ethtoolPath, err := exec.LookPath("ethtool")
	if err != nil {
		return fmt.Errorf("'ethtool' not found, cannot configure interface queues. Please install it")
	}

	if verbose {
		log.Printf("Setting interface '%s' to use %d combined queues", ifaceName, numQueues)
	}

	// Example: ethtool -L enp0s3 combined 4
	cmd := exec.Command(ethtoolPath, "-L", ifaceName, "combined", strconv.Itoa(numQueues))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set queues with '%s': %v. Output: %s", cmd.String(), err, string(out))
	}
	return nil
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

// processPacket inspects a raw packet and determines the port status.
func processPacket(pkt []byte, baseSrcPort int, numQueues int, verbose bool) (ip net.IP, port uint16, status string) {
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
	if dstPortPkt < baseSrcPort || dstPortPkt >= baseSrcPort+numQueues {
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
				continue
			}

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

// synPacker is used to quickly craft SYN packets from a template.
type synPacker struct {
	template          []byte
	ethHeaderLen      int
	ipHeaderLen       int
	ipDstOffset       int
	tcpSrcPortOffset  int
	tcpDstPortOffset  int
	tcpSeqOffset      int
	ipChecksumOffset  int
	tcpChecksumOffset int
	pseudoHeader      []byte
}

func newSynPacker(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, srcPort uint16) (*synPacker, error) {
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

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipLayer.SrcIP.To4())
	copy(pseudoHeader[4:8], ipLayer.DstIP.To4()) // DstIP is a placeholder
	pseudoHeader[8] = 0
	pseudoHeader[9] = byte(layers.IPProtocolTCP)
	tcpLen := uint16(len(tcpLayer.Contents) + len(tcpLayer.Payload))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)

	p := &synPacker{
		template:          packetBytes,
		ethHeaderLen:      ethHeaderLen,
		ipHeaderLen:       ipHeaderLen,
		ipDstOffset:       ethHeaderLen + 16,
		tcpSrcPortOffset:  ethHeaderLen + ipHeaderLen,
		tcpDstPortOffset:  ethHeaderLen + ipHeaderLen + 2,
		tcpSeqOffset:      ethHeaderLen + ipHeaderLen + 4,
		ipChecksumOffset:  ethHeaderLen + 10,
		tcpChecksumOffset: ethHeaderLen + ipHeaderLen + 16,
		pseudoHeader:      pseudoHeader,
	}

	return p, nil
}

// pack quickly constructs a packet by modifying the template.
func (p *synPacker) pack(pktBuf []byte, dstIP net.IP, srcPort, dstPort uint16, seq uint32) {
	copy(pktBuf, p.template)

	// Update headers
	copy(pktBuf[p.ipDstOffset:p.ipDstOffset+4], dstIP.To4())
	binary.BigEndian.PutUint16(pktBuf[p.tcpSrcPortOffset:p.tcpSrcPortOffset+2], srcPort)
	binary.BigEndian.PutUint16(pktBuf[p.tcpDstPortOffset:p.tcpDstPortOffset+2], dstPort)
	binary.BigEndian.PutUint32(pktBuf[p.tcpSeqOffset:p.tcpSeqOffset+4], seq)

	// Zero out checksums for recalculation.
	binary.BigEndian.PutUint16(pktBuf[p.ipChecksumOffset:p.ipChecksumOffset+2], 0)
	binary.BigEndian.PutUint16(pktBuf[p.tcpChecksumOffset:p.tcpChecksumOffset+2], 0)

	// Software checksum calculation
	ipHeader := pktBuf[p.ethHeaderLen : p.ethHeaderLen+p.ipHeaderLen]
	ipCsum := checksum(ipHeader)
	binary.BigEndian.PutUint16(pktBuf[p.ipChecksumOffset:p.ipChecksumOffset+2], ipCsum)

	// Recalculate TCP checksum
	copy(p.pseudoHeader[4:8], dstIP.To4())
	// The TCP pseudo-header's src/dst IP is already set from the template.
	// We only need to update the dstIP for the TCP checksum calculation part.
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

// tcpPseudoHeaderChecksum calculates the checksum of the TCP pseudo-header.
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

	for i := 0; i < len(pseudoHeader)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i:]))
	}

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

	isOffloadEnabled := func() bool {
		cmd := exec.Command(ethtoolPath, "-k", ifaceName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if verbose {
				log.Printf("Could not check offloading features with 'ethtool -k': %v", err)
			}
			return false
		}

		output := string(out)
		return strings.Contains(output, "tx-checksum-ip-generic: on") || strings.Contains(output, "tx-checksumming: on")
	}

	if isOffloadEnabled() {
		log.Println("Hardware TX checksum offloading is already enabled.")
		return true
	}

	log.Println("Attempting to enable hardware TX checksum offloading for performance...")
	cmd := exec.Command(ethtoolPath, "-K", ifaceName, "tx", "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: Failed to enable TX checksum offloading with 'ethtool -K %s tx on'. Error: %v", ifaceName, err)
		if len(out) > 0 {
			log.Printf("Output: %s", string(out))
		}
		log.Println("Falling back to software checksums, which may impact performance.")
		return false
	}

	if isOffloadEnabled() {
		log.Println("Successfully enabled hardware TX checksum offloading.")
		return true
	}

	log.Println("Warning: Attempted to enable hardware TX checksum offloading, but it's still disabled.")
	log.Println("Falling back to software checksums, which may impact performance.")
	return false
}
