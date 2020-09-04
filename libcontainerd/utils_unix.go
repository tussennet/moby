// +build solaris,freebsd +build !linux

package libcontainerd

import (
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func getRootIDs(s specs.Spec) (int, int, error) {
	return 0, 0, nil
}

// setPDeathSig sets the parent death signal to SIGKILL
func setSysProcAttr(sid bool) *syscall.SysProcAttr {
	return nil
}
