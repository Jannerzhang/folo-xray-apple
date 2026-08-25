// SPDX-License-Identifier: MPL-2.0
package router

import (
	"encoding/binary"
	"net"
	"sort"
)

// IsChinaIP checks if the given IP address falls within China mainland allocations (IPv4 or IPv6).
func IsChinaIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		u := binary.BigEndian.Uint32(ip4)
		return IsChinaIPv4(u)
	}
	if len(ip) == 16 {
		return IsChinaIPv6(ip)
	}
	return false
}

// IsChinaIPv4 performs an O(log N) binary search on the sorted China IPv4 ranges.
// It executes in < 30ns with 0 heap allocation.
func IsChinaIPv4(ip uint32) bool {
	n := len(chinaIPv4Ranges)
	idx := sort.Search(n, func(i int) bool {
		return chinaIPv4Ranges[i][1] >= ip
	})
	if idx < n && chinaIPv4Ranges[idx][0] <= ip {
		return true
	}
	return false
}

// IsChinaIPv6 performs an O(log N) binary search on the sorted China IPv6 ranges.
func IsChinaIPv6(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	hi := binary.BigEndian.Uint64(ip[:8])
	lo := binary.BigEndian.Uint64(ip[8:])

	n := len(chinaIPv6Ranges)
	idx := sort.Search(n, func(i int) bool {
		endHi := chinaIPv6Ranges[i][1][0]
		endLo := chinaIPv6Ranges[i][1][1]
		if endHi > hi {
			return true
		}
		if endHi == hi {
			return endLo >= lo
		}
		return false
	})

	if idx < n {
		startHi := chinaIPv6Ranges[idx][0][0]
		startLo := chinaIPv6Ranges[idx][0][1]
		if startHi < hi || (startHi == hi && startLo <= lo) {
			return true
		}
	}
	return false
}
