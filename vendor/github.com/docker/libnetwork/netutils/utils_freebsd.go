package netutils

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/docker/libnetwork/types"
)

// ElectInterfaceAddresses looks for an interface on the OS with the specified name
// and returns returns all its IPv4 and IPv6 addresses in CIDR notation.
// If a failure in retrieving the addresses or no IPv4 address is found, an error is returned.
// If the interface does not exist, it chooses from a predefined
// list the first IPv4 address which does not conflict with other
// interfaces on the system.
func ElectInterfaceAddresses(name string) ([]*net.IPNet, []*net.IPNet, error) {
	return nil, nil, types.NotImplementedErrorf("not supported on freebsd")
}

// FindAvailableNetwork returns a network from the passed list which does not
// overlap with existing interfaces in the system
func FindAvailableNetwork(list []*net.IPNet) (*net.IPNet, error) {
	for _, avail := range list {
		cidr := strings.Split(avail.String(), "/")
		ipitems := strings.Split(cidr[0], ".")
		ip := ipitems[0] + "." +
		      ipitems[1] + "." +
		      ipitems[2] + "." + "1"

		out, err := exec.Command("/sbin/route", "get", ip).Output()
		if err != nil {
			fmt.Println("failed to run route get command")
			return nil, err
		}
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			s := strings.Split(string(l), ":")
			if len(s) == 2 {
				k, v := s[0], strings.TrimSpace(s[1])
				if k == "destination" {
					if v == "default" {
						return avail, nil
					}
					break
				}
			}
		}
	}
	return nil, fmt.Errorf("no available network")
	//types.NotImplementedErrorf("not supported on freebsd")
}
