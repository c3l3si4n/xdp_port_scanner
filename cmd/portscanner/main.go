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
    )

    flag.StringVar(&ifaceName, "iface", "", "Network interface to use (mandatory)")
    flag.StringVar(&ipsArg, "ips", "", "Comma separated list of target IPv4 addresses")
    flag.StringVar(&portsArg, "ports", "1-1024", "Ports to scan, e.g. 80,443,1000-2000")
    flag.IntVar(&srcPort, "srcport", 54321, "Source TCP port to use for SYN packets")
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

    // Resolve destination MACs using ARP via pcap (best effort); fallback broadcast
    destMAC := make(map[string]net.HardwareAddr)
    handle, err := pcap.OpenLive(ifaceName, 65535, false, pcap.BlockForever)
    if err != nil {
        log.Printf("pcap open failed, will use broadcast MAC: %v", err)
    } else {
        _ = handle.Close() // not actually using yet, placeholder for potential ARP resolution logic
    }

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

    rand.Seed(time.Now().UnixNano())

    log.Printf("Starting SYN scan to %d combinations (%d IPs × %d ports) via %s", len(dests), len(ips), len(ports), ifaceName)

    // Pre-fill RX descriptors
    fillDescs := xsk.GetDescs(cap(xsk.GetDescs(0, true)), true)
    xsk.Fill(fillDescs)

    go func() {
        // transmitter goroutine
        idx := 0
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
                pkt := buildSYN(srcMAC, srcIP, srcPort, target, destMAC)
                frame := xsk.GetFrame(*d)
                copy(frame, pkt)
                d.Len = uint32(len(pkt))
            }
            xsk.Transmit(descs)
        }
    }()

    // receiver loop
    for {
        // poll with short timeout
        numRx, _, err := xsk.Poll(100)
        if err != nil {
            log.Fatalf("poll: %v", err)
        }
        if numRx == 0 {
            continue
        }
        rxDescs := xsk.Receive(numRx)
        for _, d := range rxDescs {
            frame := xsk.GetFrame(d)
            processPacket(frame, srcPort)
        }
        // Recycle RX descs
        xsk.Fill(rxDescs)
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

func buildSYN(srcMAC net.HardwareAddr, srcIP net.IP, srcPort int, dst dest, macMap map[string]net.HardwareAddr) []byte {
    dstMAC := macMap[dst.ip.String()]
    if dstMAC == nil {
        // fallback broadcast
        dstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    }

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

func processPacket(pkt []byte, srcPort int) {
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
    if flags&0x12 == 0x12 { // SYN+ACK
        srcIP := net.IPv4(pkt[26], pkt[27], pkt[28], pkt[29])
        fmt.Printf("OPEN %s:%d\n", srcIP.String(), srcPortPkt)
    }
} 