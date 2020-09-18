package daemon

import (
	"github.com/docker/docker/api/types/container"
	libcontainerdtypes "github.com/docker/docker/libcontainerd/types"
)

func toContainerdResources(resources container.Resources) *libcontainerdtypes.Resources {
	var r *libcontainerdtypes.Resources
	return r
}
