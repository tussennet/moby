package daemon

import (
	"github.com/docker/libnetwork"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
)
func getPluginExecRoot(root string) string {
	return "/run/docker/plugins"
}

func (daemon *Daemon) cleanupMountsByID(id string) error {
    return nil
}

// cleanupMounts umounts shm/mqueue mounts for old containers
func (daemon *Daemon) cleanupMounts() error {
    return nil
}

func initBridgeDriver(controller libnetwork.NetworkController, config *config.Config) error {
    // TODO
    return nil
}

func removeDefaultBridgeInterface() {
}

func (daemon *Daemon) stats(c *container.Container) (*types.StatsJSON, error) {
	s := &types.StatsJSON{}
	return s, nil
}

func (daemon *Daemon) initCgroupsPath(path string) error {
    return nil
}

func (daemon *Daemon) setupSeccompProfile() error {
	return nil
}

func setupDaemonProcess(config *config.Config) error {
	return nil
}
