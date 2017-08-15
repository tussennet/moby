// +build solaris,freebsd +build !linux

package libcontainerd

func setOOMScore(pid, score int) error {
	return nil
}
