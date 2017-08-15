// +build !linux,!windows

package libnetwork

import (
	"fmt"
	"net"
)

func (c *controller) cleanupServiceBindings(nid string) {
}

func (c *controller) addServiceBinding(name, sid, nid, eid string, vip net.IP, ingressPorts []*PortConfig, aliases []string, ip net.IP) error {
	return fmt.Errorf("not supported")
}

func (c *controller) rmServiceBinding(name, sid, nid, eid string, vip net.IP, ingressPorts []*PortConfig, aliases []string, ip net.IP) error {
	return fmt.Errorf("not supported")
}

func (c *controller) getLBIndex(sid, nid string, ingressPorts []*PortConfig) int {
	skey := serviceKey{
		id:    sid,
		ports: portConfigs(ingressPorts).String(),
	}
	c.Lock()
	s, ok := c.serviceBindings[skey]
	c.Unlock()

	if !ok {
		return 0
	}

	s.Lock()
	lb := s.loadBalancers[nid]
	s.Unlock()

	return int(lb.fwMark)
}

func (sb *sandbox) populateLoadbalancers(ep *endpoint) {
}

func arrangeIngressFilterRule() {
}
