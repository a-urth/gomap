package gomap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// scanIPRange scans an entire cidr range for open ports
// I am fairly happy with this code since its just iterating
// over scanIPPorts. Most issues are deeper in the code.
func scanIPRange(
	ctx context.Context, iprange netip.Prefix, laddr string, proto string, fastscan bool, stealth bool, ports ...int,
) (RangeScanResult, error) {
	hosts := createHostRange(iprange)

	var results RangeScanResult
	for _, h := range hosts {
		scan, err := scanIPPorts(ctx, h, laddr, proto, fastscan, stealth, ports...)
		if err != nil {
			continue
		}

		results = append(results, scan)
	}

	return results, nil
}

// scanIPPorts scans a list of ports on <hostname> <protocol>
func scanIPPorts(
	ctx context.Context, hostname string, laddr string, proto string, fastscan bool, stealth bool, ports ...int,
) (*IPScanResult, error) {
	// checks if device is online
	addr, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}

	// This gets the device name. ('/etc/hostname')
	// This is typically a good indication of if a host is 'up'
	// but can cause false-negatives in certain situations.
	hname, err := net.LookupAddr(hostname)
	if err != nil {
		hname = append(hname, "Unknown")
	}

	depth := 4
	list := make(map[int]string)

	for _, p := range ports {
		if svc, ok := detailedlist[p]; ok {
			list[p] = svc
		}
	}

	if len(list) == 0 {
		if fastscan {
			list = commonlist
			depth = 8
		} else {
			list = detailedlist
			depth = 16
		}
	}

	// Start prepping channels and vars for worker pool
	in := make(chan int)
	go func() {
		defer close(in)

		for p := range list {
			select {
			case <-ctx.Done():
				return
			case in <- p:
			}
		}
	}()

	tasks := len(list)

	// Create results channel and worker function
	resultChannel := make(chan portResult)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case port, ok := <-in:
				if !ok {
					return
				}

				service := list[port]

				if stealth {
					scanPortSyn(resultChannel, proto, hostname, service, port, laddr)
				} else {
					scanPort(resultChannel, proto, hostname, service, port)
				}
			}

		}
	}

	// Deploy a pool of workers
	for i := 0; i < depth; i++ {
		wg.Add(1)
		go worker()
	}

	var results []portResult

	var wgResult sync.WaitGroup

	wgResult.Add(1)
	go func() {
		defer wgResult.Done()
		// Combines all results from resultChannel and return a IPScanResult
		for result := range resultChannel {
			results = append(results, result)
			fmt.Printf("\033[2K\rHost: %s | Ports Scanned %d/%d", hostname, len(results), tasks)
		}
	}()

	wg.Wait()

	close(resultChannel)

	wgResult.Wait()

	return &IPScanResult{
		Hostname: hname[0],
		IP:       addr,
		Results:  results,
	}, nil
}

// scanPort scans a single ip port combo
// This detection method only works on some types of services
// but is a reasonable solution for this application
func scanPort(resultChannel chan<- portResult, protocol, hostname, service string, port int) {
	result := portResult{Port: port, Service: service}
	address := hostname + ":" + strconv.Itoa(port)

	conn, err := net.DialTimeout(protocol, address, 3*time.Second)
	if err != nil {
		result.State = false
		resultChannel <- result
		return
	}

	defer conn.Close()

	result.State = true
	resultChannel <- result
}

// scanPortSyn scans a single ip port combo using a syn-ack
// This detection method again only works on some types of services
// but is a reasonable solution for this application
func scanPortSyn(resultChannel chan<- portResult, protocol, hostname, service string, port int, laddr string) {
	result := portResult{Port: port, Service: service}
	ack := make(chan bool, 1)

	go recvSynAck(laddr, hostname, uint16(port), ack)
	sendSyn(laddr, hostname, uint16(random(10000, 65535)), uint16(port))

	select {
	case r := <-ack:
		result.State = r
		resultChannel <- result
		return
	case <-time.After(3 * time.Second):
		result.State = false
		resultChannel <- result
		return
	}
}
