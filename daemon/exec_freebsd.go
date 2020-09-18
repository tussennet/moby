package daemon

import (
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/exec"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func (daemon *Daemon) execSetPlatformOpt(c *container.Container, ec *exec.Config, p *specs.Process) error {
	return nil
}
