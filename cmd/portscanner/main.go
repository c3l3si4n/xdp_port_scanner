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
    "strings"
    "time"
    "runtime"
    "bytes"
    "bufio"
    "encoding/binary"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/slavc/xdp"
    "github.com/vishvananda/netlink"
    "golang.org/x/sys/unix"
)

func main() {
    var (
        ifaceName string
        ipsArg    string
        portsArg  string
        srcPort   int
        verbose   bool
        timeout   int
    )

    flag.StringVar(&ifaceName, "iface", "", "Network interface to use (mandatory)")
    flag.StringVar(&ipsArg, "ips", "", "Comma separated list of target IPv4 addresses")
    flag.StringVar(&portsArg, "ports", "1-1024", "Ports to scan, e.g. 80,443,1000-2000")
    flag.IntVar(&srcPort, "srcport", 54321, "Source TCP port to use for SYN packets")
    flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
    flag.IntVar(&timeout, "timeout", 5, "Seconds to wait after last packet sent before exiting")
    flag.Parse()

    if ifaceName == "" || ipsArg == "" || portsArg == "" {
        flag.Usage()
        os.Exit(1)
    }

    // Parse IPs
    var ips []net.IP
    for _, s := range strings.Split(ipsArg, ",") {
        ip := net.ParseIP(strings.TrimSpace(s)).To4()
        if ip == nil {
            log.Fatalf("invalid/unsupported IP: %s", s)
        }
        ips = append(ips, ip)
    }

    // Parse ports
    ports, err := parsePorts(portsArg)
    if err != nil {
        log.Fatalf("parse ports: %v", err)
    }

    // Build destination combinations
    var dests []dest
    for _, ip := range ips {
        for _, p := range ports {
            dests = append(dests, dest{ip: ip, port: p})
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
    defer prog.Close()

    if err := prog.Attach(link.Attrs().Index); err != nil {
        log.Fatalf("Attach program: %v", err)
    }
    defer prog.Detach(link.Attrs().Index)

    xsk, err := xdp.NewSocket(link.Attrs().Index, 0, nil)
    if err != nil {
        log.Fatalf("NewSocket: %v", err)
    }
    defer xsk.Close()

    if err := prog.Register(0, xsk.FD()); err != nil {
        log.Fatalf("Register socket in program: %v", err)
    }

    // Enable kernel busy polling on this socket (microseconds) and prefer busy poll
    const busyPollTime = 50_000 // 50 usec; tune as needed
    if err := unix.SetsockoptInt(xsk.FD(), unix.SOL_SOCKET, unix.SO_BUSY_POLL, busyPollTime); err != nil {
        log.Printf("SO_BUSY_POLL set failed (kernel <3.11 or unsupported): %v", err)
    }
    if err := unix.SetsockoptInt(xsk.FD(), unix.SOL_SOCKET, unix.SO_PREFER_BUSY_POLL, 1); err != nil {
        log.Printf("SO_PREFER_BUSY_POLL set failed: %v", err)
    }

    rand.Seed(time.Now().UnixNano())

    log.Printf("Starting SYN scan to %d combinations (%d IPs × %d ports) via %s", len(dests), len(ips), len(ports), ifaceName)

    // Pre-fill RX descriptors
    fillDescs := xsk.GetDescs(cap(xsk.GetDescs(0, true)), true)
    xsk.Fill(fillDescs)

    doneTx := make(chan struct{})
    go func() {
        runtime.LockOSThread() // keep TX loop on dedicated CPU core
        // transmitter goroutine
        idx := 0
        sent := 0
        for {
            // maintain TX completion
            if c := xsk.NumCompleted(); c > 0 {
                xsk.Complete(c)
            }

            nslots := xsk.NumFreeTxSlots()
            if nslots == 0 {
                continue
            }
            descs := xsk.GetDescs(nslots, false)
            if len(descs) == 0 {
                continue
            }
            for i := range descs {
                d := &descs[i]
                target := dests[idx]
                idx = (idx + 1) % len(dests)
                pkt := buildSYN(srcMAC, gatewayMAC, srcIP, srcPort, target)
                frame := xsk.GetFrame(*d)
                copy(frame, pkt)
                d.Len = uint32(len(pkt))
                sent++
            }
            xsk.Transmit(descs)

            if sent >= len(dests) {
                if verbose {
                    log.Printf("Transmitted all %d SYNs", sent)
                }
                break
            }
        }
        doneTx <- struct{}{}
    }()

    runtime.LockOSThread() // dedicate RX busy loop to this core

    // Track outstanding
    outstanding := make(map[string]struct{}, len(dests))
    for _, d := range dests {
        key := fmt.Sprintf("%s:%d", d.ip.String(), d.port)
        outstanding[key] = struct{}{}
    }

    lastActivity := time.Now()

    for {
        numRx := xsk.NumReceived()
        if numRx == 0 {
            // Hint CPU to reduce power while spinning
            runtime.Gosched()

            select {
            case <-doneTx:
                // wait for timeout after last packet sent
                if time.Since(lastActivity) > time.Duration(timeout)*time.Second {
                    if verbose {
                        log.Printf("Timeout reached, exiting")
                    }
                    return
                }
            default:
            }
            continue
        }
        rxDescs := xsk.Receive(numRx)
        for _, d := range rxDescs {
            frame := xsk.GetFrame(d)
            if key := processPacket(frame, srcPort, verbose); key != "" {
                delete(outstanding, key)
                if len(outstanding) == 0 {
                    fmt.Println("Scan complete")
                    return
                }
            }
        }
        // Recycle RX descs
        xsk.Fill(rxDescs)
        lastActivity = time.Now()
    }
}

type dest struct {
    ip   net.IP
    port uint16
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
func processPacket(pkt []byte, srcPort int, verbose bool) string {
    if len(pkt) < 34 { // Ethernet + IPv4 min
        return ""
    }
    if pkt[12] != 0x08 || pkt[13] != 0x00 { // not IPv4
        return ""
    }
    ipHeaderLen := (pkt[14] & 0x0F) * 4
    if len(pkt) < int(14+ipHeaderLen+20) {
        return ""
    }
    proto := pkt[23]
    if proto != 6 { // TCP
        return ""
    }
    tcpStart := 14 + ipHeaderLen
    srcPortPkt := int(pkt[tcpStart])<<8 | int(pkt[tcpStart+1])
    dstPortPkt := int(pkt[tcpStart+2])<<8 | int(pkt[tcpStart+3])
    if dstPortPkt != srcPort { // only care replies to our src port
        return ""
    }
    flags := pkt[tcpStart+13]
    if flags&0x12 == 0x12 { // SYN+ACK
        srcIP := net.IPv4(pkt[26], pkt[27], pkt[28], pkt[29])
        result := fmt.Sprintf("%s:%d", srcIP.String(), srcPortPkt)
        fmt.Printf("OPEN %s\n", result)
        return result
    }
    if verbose {
        // log non-SYN ACK responses for debugging
        srcIP := net.IPv4(pkt[26], pkt[27], pkt[28], pkt[29])
        if proto == 6 {
            srcPortPkt := int(pkt[14+ipHeaderLen])<<8 | int(pkt[14+ipHeaderLen+1])
            fmt.Printf("DEBUG reply flags %02x from %s:%d\n", pkt[14+ipHeaderLen+13], srcIP.String(), srcPortPkt)
        }
    }
    return ""
}

func getGatewayMAC(ifaceName string, srcIP, gatewayIP net.IP, verbose bool) (net.HardwareAddr, error) {
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

    if verbose {
        log.Println("Sending ARP request for gateway")
    }
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