package libnetwork

import (
	"fmt"
)

func init() {
}

func (r *resolver) setupIPTable() error {
	return fmt.Errorf("IPTables not supported on FreeBSD")
}
