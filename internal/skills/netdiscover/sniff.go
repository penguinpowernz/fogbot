package netdiscover

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

// broadcastFilter is a classic BPF program passing only ARP frames and DHCP
// requests (IPv4, UDP, unfragmented, destination port 67), so the socket
// isn't handed every packet this host sends and receives:
//
//	ldh [12]; jeq #0x806 accept
//	jeq #0x800 else drop
//	ldb [23]; jeq #17 else drop
//	ldh [20]; jset #0x1fff drop
//	ldxb 4*([14]&0xf); ldh [x+16]; jeq #67 accept else drop
var broadcastFilter = []unix.SockFilter{
	{Code: 0x28, K: 12},
	{Code: 0x15, Jt: 8, K: unix.ETH_P_ARP},
	{Code: 0x15, Jf: 8, K: unix.ETH_P_IP},
	{Code: 0x30, K: 23},
	{Code: 0x15, Jf: 6, K: unix.IPPROTO_UDP},
	{Code: 0x28, K: 20},
	{Code: 0x45, Jt: 4, K: 0x1fff},
	{Code: 0xb1, K: 14},
	{Code: 0x48, K: 16},
	{Code: 0x15, Jt: 0, Jf: 1, K: 67},
	{Code: 0x06, K: 0x40000},
	{Code: 0x06, K: 0},
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// listenBroadcasts reads ARP and DHCP broadcasts on one interface from a raw
// socket (not promiscuous: only frames this host would receive anyway) and
// sends a sighting for each sender until ctx is done.
func listenBroadcasts(ctx context.Context, iface string, out chan<- sighting) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("opening raw socket: %w", err)
	}
	defer unix.Close(fd)

	prog := unix.SockFprog{Len: uint16(len(broadcastFilter)), Filter: &broadcastFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("attaching socket filter: %w", err)
	}
	// Wake up regularly to notice ctx being cancelled
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return fmt.Errorf("binding raw socket to %s: %w", iface, err)
	}

	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return fmt.Errorf("reading raw socket: %w", err)
		}
		// Frames sent before the bind, from other interfaces, or our own
		if ll, ok := from.(*unix.SockaddrLinklayer); !ok || ll.Ifindex != ifi.Index || ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		s, ok := parseFrame(buf[:n])
		if !ok {
			continue
		}
		s.iface = iface
		s.time = time.Now()
		select {
		case out <- s:
		case <-ctx.Done():
		}
	}
	return nil
}

// parseFrame extracts the sender of an Ethernet frame carrying an ARP packet
// or a DHCP request
func parseFrame(b []byte) (sighting, bool) {
	if len(b) < 14 {
		return sighting{}, false
	}
	switch binary.BigEndian.Uint16(b[12:14]) {
	case unix.ETH_P_ARP:
		return parseARP(b[14:])
	case unix.ETH_P_IP:
		return parseDHCPFrame(b[14:])
	}
	return sighting{}, false
}

func parseARP(p []byte) (sighting, bool) {
	// Ethernet hardware, IPv4 protocol, 6 and 4 byte addresses
	if len(p) < 28 || binary.BigEndian.Uint16(p[0:2]) != 1 || binary.BigEndian.Uint16(p[2:4]) != unix.ETH_P_IP || p[4] != 6 || p[5] != 4 {
		return sighting{}, false
	}
	s := sighting{mac: cloneMAC(p[8:14]), source: "ARP"}
	// ARP probes (RFC 5227) have a sender IP of 0.0.0.0
	if ip := net.IP(p[14:18]); !ip.IsUnspecified() {
		s.ip = append(net.IP(nil), ip...)
	}
	return s, true
}

var dhcpMagic = []byte{99, 130, 83, 99}

func parseDHCPFrame(p []byte) (sighting, bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != unix.IPPROTO_UDP {
		return sighting{}, false
	}
	ihl := int(p[0]&0xf) * 4
	if ihl < 20 || len(p) < ihl+8 {
		return sighting{}, false
	}
	udp := p[ihl:]
	if binary.BigEndian.Uint16(udp[2:4]) != 67 {
		return sighting{}, false
	}
	return parseDHCP(udp[8:])
}

// parseDHCP reads a BOOTREQUEST: the client's MAC, its IP or requested IP,
// and the hostname it gives
func parseDHCP(d []byte) (sighting, bool) {
	if len(d) < 240 || d[0] != 1 || d[1] != 1 || d[2] != 6 || !bytes.Equal(d[236:240], dhcpMagic) {
		return sighting{}, false
	}
	s := sighting{mac: cloneMAC(d[28:34]), source: "DHCP"}
	if ip := net.IP(d[12:16]); !ip.IsUnspecified() {
		s.ip = append(net.IP(nil), ip...)
	}

	for opts := d[240:]; len(opts) > 0; {
		code := opts[0]
		if code == 255 {
			break
		}
		if code == 0 {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 || len(opts) < 2+int(opts[1]) {
			break
		}
		val := opts[2 : 2+int(opts[1])]
		switch code {
		case 12:
			s.hostname = cleanHostname(string(val))
		case 50:
			if len(val) == 4 && s.ip == nil {
				s.ip = append(net.IP(nil), val...)
			}
		}
		opts = opts[2+len(val):]
	}
	return s, true
}

// cleanHostname keeps a DHCP hostname printable and short: whoever sends the
// request chooses it, and it ends up in a Telegram alert and a terminal
func cleanHostname(h string) string {
	h = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) && r < unicode.MaxASCII {
			return r
		}
		return -1
	}, h)
	if len(h) > 64 {
		h = h[:64]
	}
	return h
}

func cloneMAC(b []byte) net.HardwareAddr {
	return append(net.HardwareAddr(nil), b...)
}
