//go:build linux
// +build linux

package main

import (
    "flag"
    "fmt"
    "log"
    "math/rand"
    "net"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"
    "runtime"
    "bytes"
    "bufio"
    "encoding/binary"
    "sync/atomic"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/slavc/xdp"
    "github.com/vishvananda/netlink"
    "golang.org/x/sys/unix"
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
    )

    flag.StringVar(&ifaceName, "iface", "", "Network interface to use (mandatory)")
    flag.StringVar(&ipsArg, "ips", "", "Comma separated list of target IPv4 addresses")
    flag.StringVar(&portsArg, "ports", "1-1024", "Ports to scan, e.g. 80,443,1000-2000")
    flag.IntVar(&srcPort, "srcport", 54321, "Source TCP port to use for SYN packets")
    flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
    flag.DurationVar(&retryTimeout, "retry-timeout", 1*time.Second, "Time to wait for a response before retrying a port")
    flag.IntVar(&maxRetries, "retries", 3, "Number of retries for each port before marking as filtered")
    flag.BoolVar(&showClosed, "show-closed", false, "Show closed ports in output")
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
    link, err := netlink.LinkByName(ifaceName)
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

    // Set SKB mode
    xdp.DefaultXdpFlags = unix.XDP_FLAGS_SKB_MODE

    // Prepare XDP program and socket
    prog, err := xdp.NewProgram(1) // queue 0 only
    if err != nil {
        log.Fatalf("NewProgram: %v", err)
    }

    if err := prog.Attach(link.Attrs().Index); err != nil {
        log.Fatalf("Attach program: %v", err)
    }

    cleanup := func() {
        log.Println("Detaching XDP program and closing resources...")
        if err := prog.Detach(link.Attrs().Index); err != nil {
            log.Printf("Error detaching XDP program: %v", err)
        }
        prog.Close()
    }

    c := make(chan os.Signal, 2)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-(c)
        cleanup()
        os.Exit(1)
    }()
    defer cleanup()

    // With large numbers of ports, we need larger rings. Note that this
    // may require raising the locked memory limit on your system (ulimit -l).
    socketOptions := xdp.SocketOptions{
        NumFrames:              8192,
        FrameSize:              4096,
        FillRingNumDescs:       4096,
        CompletionRingNumDescs: 4096,
        RxRingNumDescs:         4096,
        TxRingNumDescs:         4096,
    }

    xsk, err := xdp.NewSocket(link.Attrs().Index, 0, &socketOptions)
    if err != nil {
        log.Fatalf("NewSocket: %v", err)
    }
    defer xsk.Close()

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
    outstanding := make(map[string]*dest, len(dests))
    for _, d := range dests {
        key := fmt.Sprintf("%s:%d", d.ip.String(), d.port)
        outstanding[key] = d
        d.isQueued = true // It is now in the pending queue
    }

    // Stats tracking
    var totalTx, totalRx, completedCount, openCount, closedCount uint64
    go func() {
        var lastTx, lastRx, lastCompleted uint64
        lastTime := time.Now()
        ticker := time.NewTicker(2 * time.Second) // Report every 2s for less noise
        defer ticker.Stop()

        for range ticker.C {
            now := time.Now()
            elapsed := now.Sub(lastTime)
            if elapsed == 0 {
                continue
            }

            currentTx := atomic.LoadUint64(&totalTx)
            currentRx := atomic.LoadUint64(&totalRx)
            currentCompleted := atomic.LoadUint64(&completedCount)
            currentOpen := atomic.LoadUint64(&openCount)
            currentClosed := atomic.LoadUint64(&closedCount)

            txPps := float64(currentTx-lastTx) / elapsed.Seconds()
            rxPps := float64(currentRx-lastRx) / elapsed.Seconds()
            scansPerSec := float64(currentCompleted-lastCompleted) / elapsed.Seconds()

            log.Printf("Stats: TX %.0f pps, RX %.0f pps, Scans %.0f/s | Outstanding: %d | Open: %d, Closed: %d",
                txPps, rxPps, scansPerSec, len(outstanding), currentOpen, currentClosed)

            lastTx = currentTx
            lastRx = currentRx
            lastCompleted = currentCompleted
            lastTime = now
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

    for len(outstanding) > 0 {
        // 1. Send packets
        now := time.Now()
        descs := xsk.GetDescs(xsk.NumFreeTxSlots(), false)
        if len(descs) > 0 {
            packetsToSend := 0
            for i := range descs {
                var target *dest
                // Prioritize retries
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
                    break
                }

                target.isQueued = false

                pkt := buildSYN(srcMAC, gatewayMAC, srcIP, srcPort, *target)
                frame := xsk.GetFrame(descs[i])
                copy(frame, pkt)
                descs[i].Len = uint32(len(pkt))

                target.lastSent = now
                target.retries++
                packetsToSend++
            }

            if packetsToSend > 0 {
                xsk.Transmit(descs[:packetsToSend])
                atomic.AddUint64(&totalTx, uint64(packetsToSend))
            }
        }

        // 2. Receive packets
        numRx, completed, err := xsk.Poll(1) // 1ms poll timeout
        if err != nil && err != unix.EAGAIN {
            log.Printf("Poll error: %v", err)
        }
        if completed > 0 {
            xsk.Complete(completed)
        }

        if numRx > 0 {
            rxDescs := xsk.Receive(numRx)
            atomic.AddUint64(&totalRx, uint64(len(rxDescs)))
            for _, d := range rxDescs {
                frame := xsk.GetFrame(d)
                if ip, port, status := processPacket(frame, srcPort, verbose); status != "" {
                    key := fmt.Sprintf("%s:%d", ip.String(), port)
                    if target, ok := outstanding[key]; ok {
                        target.status = status
                        delete(outstanding, key)
                        atomic.AddUint64(&completedCount, 1)
                        if status == "open" {
                            atomic.AddUint64(&openCount, 1)
                            fmt.Printf("OPEN: %s\n", key)
                        } else if status == "closed" {
                            atomic.AddUint64(&closedCount, 1)
                            if showClosed {
                                fmt.Printf("CLOSED: %s\n", key)
                            }
                        }
                    }
                }
            }
            xsk.Fill(rxDescs)
        }

        // 3. Handle timeouts and retries
        now = time.Now()
        for key, target := range outstanding {
            if target.status != "unknown" {
                continue // Already handled
            }
            // Don't check timeout for something that was never sent
            if target.lastSent.IsZero() {
                continue
            }

            if now.Sub(target.lastSent) > retryTimeout {
                if target.retries >= maxRetries {
                    if verbose {
                        log.Printf("Filtered: %s", key)
                    }
                    target.status = "filtered"
                    delete(outstanding, key)
                    atomic.AddUint64(&completedCount, 1)
                } else {
                    if !target.isQueued {
                        // Add to the queue for re-transmission
                        retryDests = append(retryDests, target)
                        target.isQueued = true
                    }
                }
            }
        }
    }

    log.Printf("Scan complete. %d ports processed. Total packets transmitted: %d.", atomic.LoadUint64(&completedCount), atomic.LoadUint64(&totalTx))
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

            // Iterate over all IPs in the network.
            for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
                // Create a copy of the IP and add it to the list.
                addr := make(net.IP, len(ip))
                copy(addr, ip)
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

type dest struct {
    ip       net.IP
    port     uint16
    status   string // unknown, open, closed, filtered
    retries  int
    lastSent time.Time
    isQueued bool
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

func buildSYN(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, srcPort int, dst dest) []byte {
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
        DstIP:    dst.ip,
    }
    tcp := &layers.TCP{
        SrcPort: layers.TCPPort(srcPort),
        DstPort: layers.TCPPort(dst.port),
        Seq:     rand.Uint32(),
        SYN:     true,
        Window:  14600,
    }
    tcp.SetNetworkLayerForChecksum(ip)

    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
    _ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
    return buf.Bytes()
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

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(ifaceName, 1024, true, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("pcap open live failed: %w", err)
	}
	defer handle.Close()

	// Create ARP request
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(gatewayIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// Listen for ARP reply
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, []byte(gatewayIP.To4())) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
	return nil, fmt.Errorf("ARP reply not received from gateway")
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