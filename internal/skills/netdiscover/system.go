package netdiscover

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// neighbour is one entry of the kernel's neighbour table
type neighbour struct {
	ifindex int
	ip      net.IP
	mac     net.HardwareAddr
}

// usableNUD are the neighbour states with a confirmed MAC address; INCOMPLETE
// and FAILED entries have none, and NOARP ones are not real hosts
const usableNUD = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY | unix.NUD_PROBE | unix.NUD_PERMANENT

// readNeighbours dumps the kernel's IPv4 and IPv6 neighbour tables over netlink
func readNeighbours() ([]neighbour, error) {
	tab, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("dumping neighbour table: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("parsing neighbour table: %w", err)
	}

	var out []neighbour
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_DONE {
			break
		}
		if m.Header.Type != unix.RTM_NEWNEIGH {
			continue
		}
		if n, ok := parseNeighbour(m.Data); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// parseNeighbour decodes an RTM_NEWNEIGH payload: an ndmsg followed by
// route attributes
func parseNeighbour(b []byte) (neighbour, bool) {
	if len(b) < unix.SizeofNdMsg {
		return neighbour{}, false
	}
	family := b[0]
	ifindex := int(int32(binary.NativeEndian.Uint32(b[4:8])))
	state := binary.NativeEndian.Uint16(b[8:10])
	if state&usableNUD == 0 || (family != unix.AF_INET && family != unix.AF_INET6) {
		return neighbour{}, false
	}

	n := neighbour{ifindex: ifindex}
	for a := b[unix.SizeofNdMsg:]; len(a) >= 4; {
		l := int(binary.NativeEndian.Uint16(a[0:2]))
		typ := binary.NativeEndian.Uint16(a[2:4])
		if l < 4 || l > len(a) {
			break
		}
		data := a[4:l]
		switch typ {
		case unix.NDA_DST:
			n.ip = append(net.IP(nil), data...)
		case unix.NDA_LLADDR:
			n.mac = append(net.HardwareAddr(nil), data...)
		}
		next := (l + 3) &^ 3
		if next > len(a) {
			break
		}
		a = a[next:]
	}
	if len(n.mac) != 6 || n.ip == nil {
		return neighbour{}, false
	}
	return n, true
}

// defaultRoute is an IPv4 default route from /proc/net/route
type defaultRoute struct {
	iface   string
	gateway net.IP
	metric  int
}

// readDefaultRoutes returns the IPv4 default routes, lowest metric first
func readDefaultRoutes(path string) ([]defaultRoute, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDefaultRoutes(bufio.NewScanner(f))
}

func parseDefaultRoutes(sc *bufio.Scanner) ([]defaultRoute, error) {
	var routes []defaultRoute
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&unix.RTF_UP == 0 || flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(gw))
		r := defaultRoute{iface: f[0], gateway: ip, metric: metric}
		i := len(routes)
		for i > 0 && routes[i-1].metric > r.metric {
			i--
		}
		routes = append(routes[:i], append([]defaultRoute{r}, routes[i:]...)...)
	}
	return routes, sc.Err()
}
