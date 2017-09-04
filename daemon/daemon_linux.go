package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/libnetwork/drivers/bridge"
	"github.com/docker/docker/api/types"
	"github.com/golang/protobuf/ptypes"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/vishvananda/netlink"
)

// On Linux, plugins use a static path for storing execution state,
// instead of deriving path from daemon's exec-root. This is because
// plugin socket files are created here and they cannot exceed max
// path length of 108 bytes.
func getPluginExecRoot(root string) string {
	return "/run/docker/plugins"
}

func (daemon *Daemon) cleanupMountsByID(id string) error {
	logrus.Debugf("Cleaning up old mountid %s: start.", id)
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()

	return daemon.cleanupMountsFromReaderByID(f, id, mount.Unmount)
}

func (daemon *Daemon) cleanupMountsFromReaderByID(reader io.Reader, id string, unmount func(target string) error) error {
	if daemon.root == "" {
		return nil
	}
	var errors []string

	regexps := getCleanPatterns(id)
	sc := bufio.NewScanner(reader)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) >= 4 {
			if mnt := fields[4]; strings.HasPrefix(mnt, daemon.root) {
				for _, p := range regexps {
					if p.MatchString(mnt) {
						if err := unmount(mnt); err != nil {
							logrus.Error(err)
							errors = append(errors, err.Error())
						}
					}
				}
			}
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}

	if len(errors) > 0 {
		return fmt.Errorf("Error cleaning up mounts:\n%v", strings.Join(errors, "\n"))
	}

	logrus.Debugf("Cleaning up old mountid %v: done.", id)
	return nil
}

// cleanupMounts umounts shm/mqueue mounts for old containers
func (daemon *Daemon) cleanupMounts() error {
	return daemon.cleanupMountsByID("")
}

func getCleanPatterns(id string) (regexps []*regexp.Regexp) {
	var patterns []string
	if id == "" {
		id = "[0-9a-f]{64}"
		patterns = append(patterns, "containers/"+id+"/shm")
	}
	patterns = append(patterns, "aufs/mnt/"+id+"$", "overlay/"+id+"/merged$", "zfs/graph/"+id+"$")
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err == nil {
			regexps = append(regexps, r)
		}
	}
	return
}

func initBridgeDriver(controller libnetwork.NetworkController, config *config.Config) error {
	bridgeName := bridge.DefaultBridgeName
	if config.BridgeConfig.Iface != "" {
		bridgeName = config.BridgeConfig.Iface
	}
	netOption := map[string]string{
		bridge.BridgeName:         bridgeName,
		bridge.DefaultBridge:      strconv.FormatBool(true),
		netlabel.DriverMTU:        strconv.Itoa(config.Mtu),
		bridge.EnableIPMasquerade: strconv.FormatBool(config.BridgeConfig.EnableIPMasq),
		bridge.EnableICC:          strconv.FormatBool(config.BridgeConfig.InterContainerCommunication),
	}

	// --ip processing
	if config.BridgeConfig.DefaultIP != nil {
		netOption[bridge.DefaultBindingIP] = config.BridgeConfig.DefaultIP.String()
	}

	var (
		ipamV4Conf *libnetwork.IpamConf
		ipamV6Conf *libnetwork.IpamConf
	)

	ipamV4Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}

	nwList, nw6List, err := netutils.ElectInterfaceAddresses(bridgeName)
	if err != nil {
		return errors.Wrap(err, "list bridge addresses failed")
	}

	nw := nwList[0]
	if len(nwList) > 1 && config.BridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.BridgeConfig.FixedCIDR)
		if err != nil {
			return errors.Wrap(err, "parse CIDR failed")
		}
		// Iterate through in case there are multiple addresses for the bridge
		for _, entry := range nwList {
			if fCIDR.Contains(entry.IP) {
				nw = entry
				break
			}
		}
	}

	ipamV4Conf.PreferredPool = lntypes.GetIPNetCanonical(nw).String()
	hip, _ := lntypes.GetHostPartIP(nw.IP, nw.Mask)
	if hip.IsGlobalUnicast() {
		ipamV4Conf.Gateway = nw.IP.String()
	}

	if config.BridgeConfig.IP != "" {
		ipamV4Conf.PreferredPool = config.BridgeConfig.IP
		ip, _, err := net.ParseCIDR(config.BridgeConfig.IP)
		if err != nil {
			return err
		}
		ipamV4Conf.Gateway = ip.String()
	} else if bridgeName == bridge.DefaultBridgeName && ipamV4Conf.PreferredPool != "" {
		logrus.Infof("Default bridge (%s) is assigned with an IP address %s. Daemon option --bip can be used to set a preferred IP address", bridgeName, ipamV4Conf.PreferredPool)
	}

	if config.BridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.BridgeConfig.FixedCIDR)
		if err != nil {
			return err
		}

		ipamV4Conf.SubPool = fCIDR.String()
	}

	if config.BridgeConfig.DefaultGatewayIPv4 != nil {
		ipamV4Conf.AuxAddresses["DefaultGatewayIPv4"] = config.BridgeConfig.DefaultGatewayIPv4.String()
	}

	var deferIPv6Alloc bool
	if config.BridgeConfig.FixedCIDRv6 != "" {
		_, fCIDRv6, err := net.ParseCIDR(config.BridgeConfig.FixedCIDRv6)
		if err != nil {
			return err
		}

		// In case user has specified the daemon flag --fixed-cidr-v6 and the passed network has
		// at least 48 host bits, we need to guarantee the current behavior where the containers'
		// IPv6 addresses will be constructed based on the containers' interface MAC address.
		// We do so by telling libnetwork to defer the IPv6 address allocation for the endpoints
		// on this network until after the driver has created the endpoint and returned the
		// constructed address. Libnetwork will then reserve this address with the ipam driver.
		ones, _ := fCIDRv6.Mask.Size()
		deferIPv6Alloc = ones <= 80

		if ipamV6Conf == nil {
			ipamV6Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
		}
		ipamV6Conf.PreferredPool = fCIDRv6.String()

		// In case the --fixed-cidr-v6 is specified and the current docker0 bridge IPv6
		// address belongs to the same network, we need to inform libnetwork about it, so
		// that it can be reserved with IPAM and it will not be given away to somebody else
		for _, nw6 := range nw6List {
			if fCIDRv6.Contains(nw6.IP) {
				ipamV6Conf.Gateway = nw6.IP.String()
				break
			}
		}
	}

	if config.BridgeConfig.DefaultGatewayIPv6 != nil {
		if ipamV6Conf == nil {
			ipamV6Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
		}
		ipamV6Conf.AuxAddresses["DefaultGatewayIPv6"] = config.BridgeConfig.DefaultGatewayIPv6.String()
	}

	v4Conf := []*libnetwork.IpamConf{ipamV4Conf}
	v6Conf := []*libnetwork.IpamConf{}
	if ipamV6Conf != nil {
		v6Conf = append(v6Conf, ipamV6Conf)
	}
	// Initialize default network on "bridge" with the same name
	_, err = controller.NewNetwork("bridge", "bridge", "",
		libnetwork.NetworkOptionEnableIPv6(config.BridgeConfig.EnableIPv6),
		libnetwork.NetworkOptionDriverOpts(netOption),
		libnetwork.NetworkOptionIpam("default", "", v4Conf, v6Conf, nil),
		libnetwork.NetworkOptionDeferIPv6Alloc(deferIPv6Alloc))
	if err != nil {
		return fmt.Errorf("Error creating default \"bridge\" network: %v", err)
	}
	return nil
}


// Remove default bridge interface if present (--bridge=none use case)
func removeDefaultBridgeInterface() {
	if lnk, err := netlink.LinkByName(bridge.DefaultBridgeName); err == nil {
		if err := netlink.LinkDel(lnk); err != nil {
			logrus.Warnf("Failed to remove bridge interface (%s): %v", bridge.DefaultBridgeName, err)
		}
	}
}

func (daemon *Daemon) stats(c *container.Container) (*types.StatsJSON, error) {
	if !c.IsRunning() {
		return nil, errNotRunning{c.ID}
	}
	stats, err := daemon.containerd.Stats(c.ID)
	if err != nil {
		return nil, err
	}
	s := &types.StatsJSON{}
	cgs := stats.CgroupStats
	if cgs != nil {
		s.BlkioStats = types.BlkioStats{
			IoServiceBytesRecursive: copyBlkioEntry(cgs.BlkioStats.IoServiceBytesRecursive),
			IoServicedRecursive:     copyBlkioEntry(cgs.BlkioStats.IoServicedRecursive),
			IoQueuedRecursive:       copyBlkioEntry(cgs.BlkioStats.IoQueuedRecursive),
			IoServiceTimeRecursive:  copyBlkioEntry(cgs.BlkioStats.IoServiceTimeRecursive),
			IoWaitTimeRecursive:     copyBlkioEntry(cgs.BlkioStats.IoWaitTimeRecursive),
			IoMergedRecursive:       copyBlkioEntry(cgs.BlkioStats.IoMergedRecursive),
			IoTimeRecursive:         copyBlkioEntry(cgs.BlkioStats.IoTimeRecursive),
			SectorsRecursive:        copyBlkioEntry(cgs.BlkioStats.SectorsRecursive),
		}
		cpu := cgs.CpuStats
		s.CPUStats = types.CPUStats{
			CPUUsage: types.CPUUsage{
				TotalUsage:        cpu.CpuUsage.TotalUsage,
				PercpuUsage:       cpu.CpuUsage.PercpuUsage,
				UsageInKernelmode: cpu.CpuUsage.UsageInKernelmode,
				UsageInUsermode:   cpu.CpuUsage.UsageInUsermode,
			},
			ThrottlingData: types.ThrottlingData{
				Periods:          cpu.ThrottlingData.Periods,
				ThrottledPeriods: cpu.ThrottlingData.ThrottledPeriods,
				ThrottledTime:    cpu.ThrottlingData.ThrottledTime,
			},
		}
		mem := cgs.MemoryStats.Usage
		s.MemoryStats = types.MemoryStats{
			Usage:    mem.Usage,
			MaxUsage: mem.MaxUsage,
			Stats:    cgs.MemoryStats.Stats,
			Failcnt:  mem.Failcnt,
			Limit:    mem.Limit,
		}
		// if the container does not set memory limit, use the machineMemory
		if mem.Limit > daemon.machineMemory && daemon.machineMemory > 0 {
			s.MemoryStats.Limit = daemon.machineMemory
		}
		if cgs.PidsStats != nil {
			s.PidsStats = types.PidsStats{
				Current: cgs.PidsStats.Current,
			}
		}
	}
	s.Read, err = ptypes.Timestamp(stats.Timestamp)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (daemon *Daemon) initCgroupsPath(path string) error {
	if path == "/" || path == "." {
		return nil
	}

	if daemon.configStore.CPURealtimePeriod == 0 && daemon.configStore.CPURealtimeRuntime == 0 {
		return nil
	}

	// Recursively create cgroup to ensure that the system and all parent cgroups have values set
	// for the period and runtime as this limits what the children can be set to.
	daemon.initCgroupsPath(filepath.Dir(path))

	mnt, root, err := cgroups.FindCgroupMountpointAndRoot("cpu")
	if err != nil {
		return err
	}
	// When docker is run inside docker, the root is based of the host cgroup.
	// Should this be handled in runc/libcontainer/cgroups ?
	if strings.HasPrefix(root, "/docker/") {
		root = "/"
	}

	path = filepath.Join(mnt, root, path)
	sysinfo := sysinfo.New(true)
	if err := maybeCreateCPURealTimeFile(sysinfo.CPURealtimePeriod, daemon.configStore.CPURealtimePeriod, "cpu.rt_period_us", path); err != nil {
		return err
	}
	if err := maybeCreateCPURealTimeFile(sysinfo.CPURealtimeRuntime, daemon.configStore.CPURealtimeRuntime, "cpu.rt_runtime_us", path); err != nil {
		return err
	}
	return nil
}
