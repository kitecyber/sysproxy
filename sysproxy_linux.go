//go:build windows || linux

package sysproxy

import (
	"github.com/getlantern/byteexec"
)

var sysproxy []byte

func ensureElevatedOnDarwin(be *byteexec.Exec, prompt string, iconFullPath string) (err error) {
	return nil
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}