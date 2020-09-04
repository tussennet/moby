package libnetwork

import (
	"fmt"
)

func init() {
}

func (r *resolver) setupIPTable() error {
	return fmt.Errorf("IPTables not supported on FreeBSD") // this is just return null in old freebsd-docker
}
