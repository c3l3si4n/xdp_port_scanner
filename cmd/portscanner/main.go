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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// SystemTimers holds atomic counters for detailed performance analysis.
type SystemTimers struct {
	ioSendNs        uint64
	ioRecvNs        uint64
	ioWaitNs        uint64
	logicWaitNs     uint64
	resultProcNs    uint64
	resultTimeoutNs uint64
}

// Global channels for communication between components
var (
	packetRequestChan = make(chan PacketRequest, 16384)
	resultChan        = make(chan ScanResult, 8192)
	stateRequestChan  = make(chan StateRequest, 16384)
)

// IPTarget represents a scannable entity, either a single IP or a CIDR block.
type IPTarget interface {
	GetIP(index uint64) net.IP
	Count() uint64
	String() string
}

// SingleIPTarget represents a single IP address.
type SingleIPTarget struct {
	IP net.IP
}

func (s *SingleIPTarget) GetIP(index uint64) net.IP {
	if index == 0 {
		return s.IP
	}
	return nil
}

func (s *SingleIPTarget) Count() uint64 {
	return 1
}

func (s *SingleIPTarget) String() string {
	return s.IP.String()
}

// CIDRTarget represents a CIDR network block.
type CIDRTarget struct {
	ipNet        *net.IPNet
	firstIP      uint32
	numUsableIPs uint64
}

// NewCIDRTarget creates a new target for a CIDR range, calculating the usable IP range.
func NewCIDRTarget(ipnet *net.IPNet) *CIDRTarget {
	maskSize, bits := ipnet.Mask.Size()
	var numIPs uint64
	if bits == 32 {
		numIPs = uint64(1) << (32 - maskSize)
	} else {
		return nil // IPv6 not supported
	}

	startIP := ipnet.IP.Mask(ipnet.Mask)
	var numUsableIPs uint64

	// For subnets smaller than /31, skip network and broadcast addresses.
	if bits == 32 && maskSize < 31 {
		if numIPs > 2 {
			numUsableIPs = numIPs - 2
			inc(startIP) // Skip network address to get first usable IP
		} else {
			numUsableIPs = 0 // /31 has 2 IPs, handled below. /32 has 1.
		}
	} else {
		// For /31 and /32, all IPs are considered usable.
		numUsableIPs = numIPs
	}

	if startIP.To4() == nil {
		return nil
	}

	return &CIDRTarget{
		ipNet:        ipnet,
		firstIP:      binary.BigEndian.Uint32(startIP.To4()),
		numUsableIPs: numUsableIPs,
	}
}

func (c *CIDRTarget) GetIP(index uint64) net.IP {
	if index >= c.numUsableIPs {
		return nil
	}
	ipVal := c.firstIP + uint32(index)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipVal)
	return ip
}

func (c *CIDRTarget) Count() uint64 {
	return c.numUsableIPs
}

func (c *CIDRTarget) String() string {
	return c.ipNet.String()
}

// DestGenerator creates destination (IP, Port) pairs on demand from a set of targets.
type DestGenerator struct {
	targets []IPTarget
	ports   []uint16
	// cumulativeIPs stores the total IP count up to the start of each target.
	cumulativeIPs []uint64
	totalIPs      uint64
	totalPorts    uint64
}

// NewDestGenerator creates a generator for all scan combinations.
func NewDestGenerator(targets []IPTarget, ports []uint16) *DestGenerator {
	g := &DestGenerator{
		targets:       targets,
		ports:         ports,
		cumulativeIPs: make([]uint64, len(targets)),
		totalPorts:    uint64(len(ports)),
	}
	var currentTotal uint64
	for i, t := range targets {
		g.cumulativeIPs[i] = currentTotal
		currentTotal += t.Count()
	}
	g.totalIPs = currentTotal
	return g
}

// GetDestForIndex returns the IP and port for a given global scan index.
// The index maps to a unique (IP, Port) combination.
func (g *DestGenerator) GetDestForIndex(index uint64) (net.IP, uint16) {
	if g.totalPorts == 0 || g.totalIPs == 0 {
		return nil, 0
	}

	portIndex := index % g.totalPorts
	ipIndex := index / g.totalPorts

	port := g.ports[portIndex]

	// Find the correct IP target for the global IP index.
	for i, target := range g.targets {
		if ipIndex < g.cumulativeIPs[i]+target.Count() {
			ip := target.GetIP(ipIndex - g.cumulativeIPs[i])
			return ip, port
		}
	}
	return nil, 0 // Should not happen if index is within bounds
}

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
		txRingSize   int
		rxRingSize   int
		numQueues    int
		numWorkers   int
		timers       SystemTimers
	)

	flag.StringVar(&ifaceName, "iface", "", "Network interface to use (mandatory)")
	flag.StringVar(&ipsArg, "ips", "", "Comma separated list of target IPv4 addresses and CIDR blocks")
	flag.StringVar(&portsArg, "ports", "1-1024", "Ports to scan, e.g. 80,443,1000-2000")
	flag.IntVar(&srcPort, "srcport", 54321, "Source TCP port to use for SYN packets")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.DurationVar(&retryTimeout, "retry-timeout", 1*time.Second, "Time to wait for a response before retrying a port")
	flag.IntVar(&maxRetries, "retries", 3, "Number of retries for each port before marking as filtered")
	flag.BoolVar(&showClosed, "show-closed", false, "Show closed ports in output")
	flag.IntVar(&ringSize, "ring-size", 4096, "Default AF_XDP ring size for all rings if not specified otherwise.")
	flag.IntVar(&txRingSize, "tx-ring-size", 0, "Transmit/Completion ring size (defaults to ring-size).")
	flag.IntVar(&rxRingSize, "rx-ring-size", 0, "Receive/Fill ring size (defaults to ring-size).")
	flag.IntVar(&numQueues, "num-queues", 1, "Number of NIC queues to use for parallel scanning.")
	flag.IntVar(&numWorkers, "workers", runtime.NumCPU(), "Number of logic worker goroutines")
	flag.Parse()

	if ifaceName == "" || ipsArg == "" || portsArg == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Set specific ring sizes, defaulting to the general ring-size.
	if txRingSize == 0 {
		txRingSize = ringSize
	}
	if rxRingSize == 0 {
		rxRingSize = ringSize
	}

	// Configure the network interface to use the specified number of queues.
	if err := configureInterfaceQueues(ifaceName, numQueues, verbose); err != nil {
		log.Fatalf("Could not configure interface queues: %v", err)
	}

	// Parse IPs and CIDRs into targets.
	ipTargets, err := parseIPTargets(ipsArg)
	if err != nil {
		log.Fatalf("could not parse 'ips' argument: %v", err)
	}

	// Parse ports
	ports, err := parsePorts(portsArg)
	if err != nil {
		log.Fatalf("parse ports: %v", err)
	}

	// Create a destination generator.
	destGen := NewDestGenerator(ipTargets, ports)
	totalScans := destGen.totalIPs * destGen.totalPorts

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

	// Global stats
	var totalTx, totalRx, completedCount, openCount, closedCount uint64
	var totalResponseTimeNs, totalResponsesWithTime uint64 // For avg response time

	// Create and shuffle scan indices for randomization
	scanIndices := make([]uint64, totalScans)
	for i := uint64(0); i < totalScans; i++ {
		scanIndices[i] = i
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(scanIndices), func(i, j int) {
		scanIndices[i], scanIndices[j] = scanIndices[j], scanIndices[i]
	})
	var sharedIndexCounter int64 = -1

	log.Printf("Starting SYN scan to %d combinations (%d IPs × %d ports) via %s using %d queues and %d workers",
		totalScans, destGen.totalIPs, destGen.totalPorts, ifaceName, numQueues, numWorkers)
	startTime := time.Now()

	// Start Result Processor (must start before others)
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go resultProcessor(done, &resultWg, retryTimeout, maxRetries, verbose, showClosed,
		&completedCount, &openCount, &closedCount, int(totalScans), &totalResponseTimeNs, &totalResponsesWithTime, &timers)

	// Start I/O Worker
	var ioWg sync.WaitGroup
	ioWg.Add(1)
	go ioWorker(done, &ioWg, iface.Attrs().Index, prog, numQueues, txRingSize, rxRingSize, srcMAC, gatewayMAC, srcIP, srcPort,
		verbose, &totalTx, &totalRx, &timers)

	// Start Logic Workers
	var logicWg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		logicWg.Add(1)
		go logicWorker(done, &logicWg, destGen, scanIndices, &sharedIndexCounter, i, int(totalScans), &timers)
	}

	// Stats reporting goroutine
	var statsWg sync.WaitGroup
	statsWg.Add(1)
	go func() {
		defer statsWg.Done()
		var (
			lastTx, lastRx, lastCompleted uint64
			lastTimers                    SystemTimers
			lastTime                      = time.Now()
		)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				intervalNs := float64(now.Sub(lastTime).Nanoseconds())
				lastTime = now

				currentTx := atomic.LoadUint64(&totalTx)
				currentRx := atomic.LoadUint64(&totalRx)
				currentCompleted := atomic.LoadUint64(&completedCount)

				txPps := float64(currentTx-lastTx) / (intervalNs / 1e9)
				rxPps := float64(currentRx-lastRx) / (intervalNs / 1e9)
				scansPerSec := float64(currentCompleted-lastCompleted) / (intervalNs / 1e9)
				outstandingCount := int(totalScans) - int(currentCompleted)

				// Calculate average response time
				avgRspTimeMs := 0.0
				if responses := atomic.LoadUint64(&totalResponsesWithTime); responses > 0 {
					avgRspTimeMs = float64(atomic.LoadUint64(&totalResponseTimeNs)) / float64(responses) / 1e6
				}

				// Calculate time percentages
				currentTimers := SystemTimers{
					ioSendNs:        atomic.LoadUint64(&timers.ioSendNs),
					ioRecvNs:        atomic.LoadUint64(&timers.ioRecvNs),
					ioWaitNs:        atomic.LoadUint64(&timers.ioWaitNs),
					logicWaitNs:     atomic.LoadUint64(&timers.logicWaitNs),
					resultProcNs:    atomic.LoadUint64(&timers.resultProcNs),
					resultTimeoutNs: atomic.LoadUint64(&timers.resultTimeoutNs),
				}

				ioSendPct := float64(currentTimers.ioSendNs-lastTimers.ioSendNs) / intervalNs * 100
				ioRecvPct := float64(currentTimers.ioRecvNs-lastTimers.ioRecvNs) / intervalNs * 100
				ioWaitPct := float64(currentTimers.ioWaitNs-lastTimers.ioWaitNs) / intervalNs * 100
				logicWaitPct := float64(currentTimers.logicWaitNs-lastTimers.logicWaitNs) / intervalNs * 100
				resultProcPct := float64(currentTimers.resultProcNs-lastTimers.resultProcNs) / intervalNs * 100
				resultTimeoutPct := float64(currentTimers.resultTimeoutNs-lastTimers.resultTimeoutNs) / intervalNs * 100

				lastTimers = currentTimers

				log.Printf("Stats: TX %.0f pps, RX %.0f pps, Scans %.0f/s | Outstanding: %d | Avg Rsp: %.2fms",
					txPps, rxPps, scansPerSec, outstandingCount, avgRspTimeMs)

				var bottleneck string
				if ioWaitPct > 50 {
					bottleneck = "CPU Bound (Logic Workers)"
				} else if logicWaitPct > 50 {
					bottleneck = "I/O Bound (Network)"
				} else {
					bottleneck = "Balanced"
				}

				log.Printf("--> Bottleneck: %s | Timings (%%): LogicWait: %.1f, IOWait: %.1f, IOSend: %.1f, IORecv: %.1f, ResultProc: %.1f, TimeoutProc: %.1f",
					bottleneck, logicWaitPct, ioWaitPct, ioSendPct, ioRecvPct, resultProcPct, resultTimeoutPct)
				log.Printf("--> Channels: Requests: %d/%d, Results: %d/%d",
					len(packetRequestChan), cap(packetRequestChan), len(resultChan), cap(resultChan))

				lastTx = currentTx
				lastRx = currentRx
				lastCompleted = currentCompleted

				if currentCompleted >= totalScans {
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
		if completed >= totalScans {
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

// Logic Worker: generates packet requests by pulling indices from a shared, shuffled list.
func logicWorker(done <-chan struct{}, wg *sync.WaitGroup, gen *DestGenerator,
	indices []uint64, sharedIndex *int64, workerID int, totalScans int, timers *SystemTimers) {
	defer wg.Done()

	for {
		// Atomically get the next index to process.
		myIndex := atomic.AddInt64(sharedIndex, 1)
		if myIndex >= int64(totalScans) {
			return // All work is claimed.
		}

		// Get the actual destination for our shuffled index.
		shuffledIdx := indices[myIndex]
		ip, port := gen.GetDestForIndex(shuffledIdx)
		if ip == nil {
			continue // Should not happen with valid indices.
		}

		startWait := time.Now()
		select {
		case <-done:
			atomic.AddUint64(&timers.logicWaitNs, uint64(time.Since(startWait).Nanoseconds()))
			return
		case packetRequestChan <- PacketRequest{IP: ip, Port: port}:
			atomic.AddUint64(&timers.logicWaitNs, uint64(time.Since(startWait).Nanoseconds()))
			// Also notify the result processor to track this target
			startWait = time.Now()
			select {
			case stateRequestChan <- StateRequest{
				IP:       ip,
				Port:     port,
				Action:   "add",
				LastSent: time.Now(),
				Retries:  1,
			}:
				atomic.AddUint64(&timers.logicWaitNs, uint64(time.Since(startWait).Nanoseconds()))
			case <-done:
				atomic.AddUint64(&timers.logicWaitNs, uint64(time.Since(startWait).Nanoseconds()))
				return
			}
		}
	}
}

// I/O Worker: handles all XDP socket operations.
// It prioritizes sending packets and periodically checks for receives to avoid TX starvation.
func ioWorker(done <-chan struct{}, wg *sync.WaitGroup, ifIndex int, prog *xdp.Program, numQueues, txRingSize, rxRingSize int,
	srcMAC, gatewayMAC net.HardwareAddr, srcIP net.IP, srcPort int, verbose bool, totalTx, totalRx *uint64, timers *SystemTimers) {
	defer wg.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create XDP sockets for all queues
	var sockets []*xdp.Socket
	socketOptions := xdp.SocketOptions{
		NumFrames:              txRingSize + rxRingSize,
		FrameSize:              4096,
		FillRingNumDescs:       rxRingSize,
		CompletionRingNumDescs: txRingSize,
		RxRingNumDescs:         rxRingSize,
		TxRingNumDescs:         txRingSize,
	}

	for i := 0; i < numQueues; i++ {
		xsk, err := xdp.NewSocket(ifIndex, i, &socketOptions)
		if err != nil {
			log.Fatalf("NewSocket for queue %d: %v", i, err)
		}
		defer xsk.Close()

		// For the primary RX queue (0), we need to register it with the BPF program.
		if i == 0 {
			if err := prog.Register(i, xsk.FD()); err != nil {
				log.Fatalf("Register socket for queue %d: %v", i, err)
			}
			defer prog.Unregister(i)
		}

		sockets = append(sockets, xsk)
	}

	packer, err := newSynPacker(srcMAC, gatewayMAC, srcIP, uint16(srcPort))
	if err != nil {
		log.Fatalf("failed to create syn packet generator: %v", err)
	}

	// Pre-fill RX rings for all sockets that have one.
	for _, xsk := range sockets {
		if rxRingSize > 0 {
			if fillDescs := xsk.GetDescs(xsk.NumFreeFillSlots(), true); len(fillDescs) > 0 {
				xsk.Fill(fillDescs)
			}
		}
	}

	var (
		requestsToSend []PacketRequest
		seq            uint32 = rand.Uint32()
		currentQueue   int    = 0
	)

	// Use a ticker to periodically trigger the RX path.
	rxCheckTicker := time.NewTicker(2 * time.Millisecond)
	defer rxCheckTicker.Stop()

	for {
		select {
		case <-done:
			return
		case <-rxCheckTicker.C:
			// ---- RX PATH (Low Priority) ----
			startRecv := time.Now()
			// Only need to check for receives on queue 0.
			rxSocket := sockets[0]
			numRx, numComp, err := rxSocket.Poll(0)
			if err != nil && err != unix.EAGAIN && err != unix.EINTR && err != unix.EBADF {
				log.Printf("Poll error on RX queue 0: %v", err)
			}

			// Handle completions that came in with the poll
			if numComp > 0 {
				rxSocket.Complete(numComp)
			}

			if numRx > 0 {
				rxDescs := rxSocket.Receive(numRx)
				processedPackets := 0
				for _, d := range rxDescs {
					frame := rxSocket.GetFrame(d)
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
				}
				rxSocket.Fill(rxDescs)
			}
			atomic.AddUint64(&timers.ioRecvNs, uint64(time.Since(startRecv).Nanoseconds()))

		default:
			// ---- TX PATH (High Priority) ----
			xsk := sockets[currentQueue]

			// We must process completions to free up TX ring slots.
			// We can ignore RX results here as they are handled by the ticker case.
			_, numComp, _ := xsk.Poll(0)
			if numComp > 0 {
				xsk.Complete(numComp)
			}

			// Top up our internal send buffer with new requests.
		GetNewRequests:
			for len(requestsToSend) < BATCH_SIZE*2 {
				select {
				case req := <-packetRequestChan:
					requestsToSend = append(requestsToSend, req)
				default:
					break GetNewRequests
				}
			}

			// Send packets from our buffer.
			startSend := time.Now()
			if len(requestsToSend) > 0 {
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
			}
			atomic.AddUint64(&timers.ioSendNs, uint64(time.Since(startSend).Nanoseconds()))
			currentQueue = (currentQueue + 1) % numQueues

			// If completely idle, yield to avoid pegging the CPU.
			if len(requestsToSend) == 0 && len(packetRequestChan) == 0 {
				startWait := time.Now()
				runtime.Gosched()
				atomic.AddUint64(&timers.ioWaitNs, uint64(time.Since(startWait).Nanoseconds()))
			}
		}
	}
}

// Result Processor: manages all state and handles results
func resultProcessor(done <-chan struct{}, wg *sync.WaitGroup, retryTimeout time.Duration, maxRetries int,
	verbose, showClosed bool, completedCount, openCount, closedCount *uint64, totalTargets int,
	totalResponseTimeNs, totalResponsesWithTime *uint64, timers *SystemTimers) {
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
			startTimeout := time.Now()
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
			atomic.AddUint64(&timers.resultTimeoutNs, uint64(time.Since(startTimeout).Nanoseconds()))

		case req := <-stateRequestChan:
			startResult := time.Now()
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
			atomic.AddUint64(&timers.resultProcNs, uint64(time.Since(startResult).Nanoseconds()))
		case result := <-resultChan:
			startResult := time.Now()
			key := makeDestKey(result.IP, result.Port)
			if target, ok := outstanding[key]; ok {
				// Record response time before changing state
				duration := time.Since(target.lastSent).Nanoseconds()
				atomic.AddUint64(totalResponseTimeNs, uint64(duration))
				atomic.AddUint64(totalResponsesWithTime, 1)

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
			atomic.AddUint64(&timers.resultProcNs, uint64(time.Since(startResult).Nanoseconds()))
		}
	}
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

func parseIPTargets(s string) ([]IPTarget, error) {
	var targets []IPTarget
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
			target := NewCIDRTarget(ipnet)
			if target != nil && target.Count() > 0 {
				targets = append(targets, target)
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
			targets = append(targets, &SingleIPTarget{IP: ip})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid IPs or CIDRs found")
	}
	return targets, nil
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
