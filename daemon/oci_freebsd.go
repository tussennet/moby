package daemon // import "github.com/docker/docker/daemon"

import (
	"errors"

	"github.com/docker/docker/container"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func (daemon *Daemon) createSpec(c *container.Container) (retSpec *specs.Spec, err error) {
	return nil, errors.New("not implemented")
}
