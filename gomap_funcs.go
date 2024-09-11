package gomap

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
)

func canSocketBind(laddr string) bool {
	// Check if user can listen on socket
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return false
	}

	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

// createHostRange converts a input ip addr string to a slice of ips on the cidr
func createHostRange(netw netip.Prefix) []string {
	_, ipv4Net, err := net.ParseCIDR(netw.Masked().String())
	if err != nil {
		log.Fatal(err)
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)

	var hosts []string
	for i := start; i <= finish; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}

	return hosts
}

// getLocalRange returns local ip range or defaults on error to most common
func getLocalRange() netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.MustParsePrefix("192.168.1.0/24")
	}

	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if v4 := ipnet.IP.To4(); v4 != nil {
				netip.PrefixFrom(netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}), 24)
			}
		}
	}

	return netip.MustParsePrefix("192.168.1.0/24")
}

// getLocalRange returns local ip range or defaults on error to most common
func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), err
			}
		}
	}
	return "", fmt.Errorf("no IP found")
}
