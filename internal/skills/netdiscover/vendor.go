package netdiscover

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// ouiFiles are where Debian's ieee-data and hwdata packages put the IEEE OUI list
var ouiFiles = []string{
	"/usr/share/ieee-data/oui.txt",
	"/usr/share/hwdata/oui.txt",
	"/usr/share/misc/oui.txt",
}

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
)

// macVendor names the maker of a MAC address from the local OUI list. A
// locally administered address, as phones use for privacy, has no maker.
func macVendor(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	if mac[0]&0x02 != 0 {
		return "randomised MAC"
	}
	ouiOnce.Do(func() {
		for _, path := range ouiFiles {
			if f, err := os.Open(path); err == nil {
				ouiTable = parseOUI(f)
				f.Close()
				return
			}
		}
	})
	return ouiTable[strings.ToUpper(strings.ReplaceAll(mac.String()[:8], ":", ""))]
}

// parseOUI reads the "XXXXXX     (base 16)		Vendor" lines of an IEEE OUI list
func parseOUI(r io.Reader) map[string]string {
	table := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		prefix, vendor, ok := strings.Cut(sc.Text(), "(base 16)")
		prefix = strings.TrimSpace(prefix)
		if !ok || len(prefix) != 6 {
			continue
		}
		table[strings.ToUpper(prefix)] = strings.TrimSpace(vendor)
	}
	return table
}
