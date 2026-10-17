package netdiscover

import (
	"bufio"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func rtattr(typ uint16, data []byte) []byte {
	b := make([]byte, 4, 4+len(data)+3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(data)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func ndmsg(family byte, ifindex int32, state uint16, attrs ...[]byte) []byte {
	b := make([]byte, unix.SizeofNdMsg)
	b[0] = family
	binary.NativeEndian.PutUint32(b[4:8], uint32(ifindex))
	binary.NativeEndian.PutUint16(b[8:10], state)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func TestParseNeighbour(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	b := ndmsg(unix.AF_INET, 3, unix.NUD_STALE, rtattr(unix.NDA_DST, []byte{192, 168, 1, 7}), rtattr(unix.NDA_LLADDR, mac))
	n, ok := parseNeighbour(b)
	if !ok || n.ifindex != 3 || n.ip.String() != "192.168.1.7" || n.mac.String() != mac.String() {
		t.Fatalf("got %+v %v", n, ok)
	}

	ip6 := net.ParseIP("fe80::1")
	if n, ok := parseNeighbour(ndmsg(unix.AF_INET6, 2, unix.NUD_REACHABLE, rtattr(unix.NDA_DST, ip6), rtattr(unix.NDA_LLADDR, mac))); !ok || !n.ip.Equal(ip6) {
		t.Errorf("IPv6 neighbour not parsed: %+v", n)
	}
	if _, ok := parseNeighbour(ndmsg(unix.AF_INET, 3, unix.NUD_INCOMPLETE, rtattr(unix.NDA_DST, []byte{192, 168, 1, 8}))); ok {
		t.Error("incomplete entry should be skipped")
	}
	if _, ok := parseNeighbour(ndmsg(unix.AF_INET, 3, unix.NUD_FAILED, rtattr(unix.NDA_DST, []byte{192, 168, 1, 8}), rtattr(unix.NDA_LLADDR, mac))); ok {
		t.Error("failed entry should be skipped")
	}
	if _, ok := parseNeighbour(b[:8]); ok {
		t.Error("short message should be rejected")
	}
}

func TestParseDefaultRoutes(t *testing.T) {
	in := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
enp0s31f6	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
enp0s31f6	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	routes, err := parseDefaultRoutes(bufio.NewScanner(strings.NewReader(in)))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].iface != "enp0s31f6" || routes[0].gateway.String() != "192.168.1.1" || routes[1].gateway.String() != "192.168.1.254" {
		t.Fatalf("got %+v", routes)
	}
}

func ethernet(ethertype uint16, payload []byte) []byte {
	b := make([]byte, 14)
	copy(b, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(b[12:14], ethertype)
	return append(b, payload...)
}

func TestParseFrame_ARP(t *testing.T) {
	arp := []byte{0, 1, 8, 0, 6, 4, 0, 1,
		0x3c, 0x22, 0xfb, 1, 2, 3, 192, 168, 1, 50,
		0, 0, 0, 0, 0, 0, 192, 168, 1, 1}
	s, ok := parseFrame(ethernet(unix.ETH_P_ARP, arp))
	if !ok || s.mac.String() != "3c:22:fb:01:02:03" || s.ip.String() != "192.168.1.50" || s.source != "ARP" {
		t.Fatalf("got %+v %v", s, ok)
	}

	// An ARP probe has no sender IP
	copy(arp[14:18], []byte{0, 0, 0, 0})
	if s, ok := parseFrame(ethernet(unix.ETH_P_ARP, arp)); !ok || s.ip != nil {
		t.Errorf("probe: got %+v %v", s, ok)
	}
}

func dhcpRequest(mac []byte, opts ...byte) []byte {
	d := make([]byte, 240)
	d[0], d[1], d[2] = 1, 1, 6
	copy(d[28:], mac)
	copy(d[236:], dhcpMagic)
	return append(append(d, opts...), 255)
}

func udpIP(dport uint16, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = unix.IPPROTO_UDP
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 68)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	return append(append(ip, udp...), payload...)
}

func TestParseFrame_DHCP(t *testing.T) {
	mac := []byte{0x3c, 0x22, 0xfb, 9, 9, 9}
	req := dhcpRequest(mac,
		53, 1, 3,
		50, 4, 192, 168, 1, 77,
		12, 7, 'p', 'h', 'o', 'n', 'e', 0x1b, '!')
	s, ok := parseFrame(ethernet(unix.ETH_P_IP, udpIP(67, req)))
	if !ok || s.mac.String() != "3c:22:fb:09:09:09" || s.ip.String() != "192.168.1.77" || s.source != "DHCP" {
		t.Fatalf("got %+v %v", s, ok)
	}
	if s.hostname != "phone!" {
		t.Errorf("hostname should have the escape stripped, got %q", s.hostname)
	}

	if _, ok := parseFrame(ethernet(unix.ETH_P_IP, udpIP(68, req))); ok {
		t.Error("DHCP reply port should be ignored")
	}
	if _, ok := parseFrame(ethernet(unix.ETH_P_IP, udpIP(67, req[:200]))); ok {
		t.Error("truncated DHCP should be rejected")
	}
	// Option claiming more bytes than are left
	bad := dhcpRequest(mac)
	bad = append(bad[:len(bad)-1], 12, 50, 'x')
	if s, ok := parseFrame(ethernet(unix.ETH_P_IP, udpIP(67, bad))); !ok || s.hostname != "" {
		t.Errorf("overlong option: got %+v %v", s, ok)
	}
}

func TestParseOUI(t *testing.T) {
	in := `OUI/MA-L			Organization
3C-22-FB   (hex)		Apple, Inc.
3C22FB     (base 16)		Apple, Inc.
				1 Infinite Loop
`
	table := parseOUI(strings.NewReader(in))
	if table["3C22FB"] != "Apple, Inc." || len(table) != 1 {
		t.Fatalf("got %v", table)
	}
}

func TestMACVendor_Randomised(t *testing.T) {
	mac, _ := net.ParseMAC("da:a1:19:00:00:01")
	if v := macVendor(mac); v != "randomised MAC" {
		t.Errorf("got %q", v)
	}
}
