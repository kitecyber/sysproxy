// Package sysproxy provides macOS-specific implementation for system proxy management.
// This file contains the Darwin/macOS platform-specific code including the embedded
// universal binary (amd64/arm64) and privilege elevation logic.
package sysproxy

import (
	_ "embed"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/elevate"
)

// Note this is a universal binary that runs on amd64 and arm64
//
//go:embed binaries/darwin/sysproxy
var sysproxy []byte

// ensureElevatedOnDarwin ensures that the helper tool has root:wheel ownership
// and setuid bit set, which is required for the tool to modify system-wide proxy settings.
// If the tool is not properly configured, it requests elevation through a system dialog.
//
// Parameters:
//   - be: the byteexec instance containing the helper tool
//   - prompt: the message to display in the elevation dialog
//   - iconFullPath: the full path to the icon to display in the elevation dialog
//
// Returns an error if elevation fails or if the tool cannot be configured properly.
func ensureElevatedOnDarwin(be *byteexec.Exec, prompt string, iconFullPath string) (err error) {
	var s syscall.Stat_t
	// we just checked its existence, not bother checking specific error again
	if err = syscall.Stat(be.Filename, &s); err != nil {
		return fmt.Errorf("error starting helper tool %s: %v", be.Filename, err)
	}
	if s.Mode&syscall.S_ISUID > 0 && s.Uid == 0 && s.Gid == 0 {
		log.Tracef("%v is already owned by root:wheel and has setuid bit on", be.Filename)
		return
	}
	cmd := elevate.WithPrompt(prompt).WithIcon(iconFullPath).Command(be.Filename, "setuid")
	return run(cmd)
}

// detach configures the command to run in a new process group, detached from
// the parent process. This prevents the child process from being terminated
// when the parent exits and allows it to continue running independently.
//
// On macOS, this is achieved by setting the Setpgid flag in SysProcAttr.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

// SetBypass configures the proxy bypass list for the specified network service.
// The bypass list contains addresses or domains that should not use the proxy.
//
// Parameters:
//   - service: the network service identifier (e.g., "Wi-Fi", "Ethernet")
//   - list: comma-separated list of domains or addresses to bypass
//
// Returns an error if the operation fails or if EnsureHelperToolPresent has not been called.
func SetBypass(service, list string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("setbypass", service, list)
	err := run(cmd)
	if err != nil {
		log.Errorf("Unable to set bypasslist %v", err)
		return err
	}
	return nil
}

// UnSetBypass clears the proxy bypass list for the specified network service.
//
// Parameters:
//   - service: the network service identifier (e.g., "Wi-Fi", "Ethernet")
//
// Returns an error if the operation fails or if EnsureHelperToolPresent has not been called.
func UnSetBypass(service string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("unsetbypass", service)
	err := run(cmd)
	if err != nil {
		log.Errorf("Unable to set bypasslist %v", err)
		return err
	}
	return nil
}

// GetBypass retrieves the current proxy bypass list for the specified network service.
//
// Parameters:
//   - service: the network service identifier (e.g., "Wi-Fi", "Ethernet")
//
// Returns the bypass list as a string (comma-separated), or an error if the operation fails
// or if EnsureHelperToolPresent has not been called.
func GetBypass(service string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("getbypass", service)
	out, err := cmd.Output()
	if err != nil {
		log.Errorf("Unable to get bypasslist %v", err)
		return "", err
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
