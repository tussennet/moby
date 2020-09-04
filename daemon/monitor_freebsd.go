package daemon

import (
	"github.com/docker/docker/container"
	"github.com/docker/docker/libcontainerd/types"
)

// platformConstructExitStatus returns a platform specific exit status structure
func platformConstructExitStatus(e types.StateInfo) *container.ExitStatus {
	return &container.ExitStatus{
		ExitCode: int(e.ExitCode),
	}
}

// postRunProcessing perfoms any processing needed on the container after it has stopped.
func (daemon *Daemon) postRunProcessing(container *container.Container, e types.StateInfo) error {
	return nil
}
