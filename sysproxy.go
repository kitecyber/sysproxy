// Package sysproxy provides a cross-platform library for managing system proxy settings.
// It supports Windows, macOS, and Linux platforms by embedding platform-specific
// helper binaries and executing them to configure system-wide proxy settings.
//
// The library ensures thread-safe operations and provides automatic cleanup mechanisms
// to restore proxy settings when the application terminates.
package sysproxy

import (
	_ "embed"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("sysproxy")

	mu sync.Mutex
	be *byteexec.Exec
)

// EnsureHelperToolPresent checks if helper tool exists and extracts it if not.
// On Mac OS, it also checks and set the file's owner to root:wheel and the setuid bit,
// it will request user to input password through a dialog to gain the rights to do so.
// path: absolute or relative path of the file to be checked and generated if
// not exists. Note - relative paths are resolved relative to the system-
// specific folder for aplication resources.
// prompt: the message to be shown on the dialog.
// iconPath: the full path of the icon to be shown on the dialog.
func EnsureHelperToolPresent(path string, prompt string, iconFullPath string) (err error) {
	mu.Lock()
	defer mu.Unlock()
	if len(sysproxy) == 0 {
		return fmt.Errorf("unable to find binary: %v", sysproxy)
	}
	be, err = byteexec.New(sysproxy, path)
	if err != nil {
		return fmt.Errorf("unable to extract helper tool: %v", err)
	}
	return ensureElevatedOnDarwin(be, prompt, iconFullPath)
}

// On tells OS to configure proxy through `addr` as host:port. It always returns
// a function that can be used to clear the system proxy setting. If the current
// process terminates before the clear function is called, the system proxy
// setting will be cleared anyway.
func On(addr string) (func() error, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse address %v: %v", addr, err)
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}

	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return nil, fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("on", host, port)
	onErr := run(cmd)

	// Unlock before calling waitAndCleanup to avoid holding lock during background process setup
	off, offErr := waitAndCleanup(host, port, &mu, be)
	if offErr != nil {
		log.Errorf("Unable to prepare waitAndCleanup job: %v", offErr)
	}
	if onErr != nil {
		return off, onErr
	}

	verifyErr := verifyUnlocked(addr)
	return off, verifyErr
}

// Off immediately unsets the proxy at addr as the system proxy.
func Off(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("unable to parse address %v: %v", addr, err)
	}

	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("off", host, port)
	if err := run(cmd); err != nil {
		return err
	}
	return verifyUnlocked("")
}

// Show retrieves the current system proxy configuration.
// Returns the proxy address as a string, or an error if the operation fails.
func Show() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("show")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// resultType holds the result of an asynchronous command execution.
type resultType struct {
	out []byte
	err error
}

// waitAndCleanup starts a detached background process that waits for stdin to be closed,
// then cleans up the system proxy settings. It returns a cleanup function that, when called,
// closes the stdin of the detached process to trigger the cleanup operation.
//
// The cleanup function waits up to 30 seconds for the process to complete and properly
// reaps the process to prevent zombie processes. If the timeout is exceeded, the process
// is killed forcefully.
//
// Parameters:
//   - host: the proxy host to clean up
//   - port: the proxy port to clean up
//   - mutex: the mutex to use when verifying the cleanup
//   - exec: the byteexec instance to use for executing the cleanup command
//
// Returns a cleanup function and an error if the process fails to start.
func waitAndCleanup(host string, port string, mutex *sync.Mutex, exec *byteexec.Exec) (func() error, error) {
	cmd := exec.Command("wait-and-cleanup", host, port)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	// Set up the command to run as a detached process
	detach(cmd)
	resultCh := make(chan *resultType)

	// Start the command once
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Release process resources to prevent zombie processes
	// This is safe because we're using Wait() to properly reap the process
	go func() {
		err := cmd.Wait()
		// After Wait() completes, the process resources are reaped
		resultCh <- &resultType{
			out: nil,
			err: err,
		}
	}()

	return func() error {
		stdin.Close()

		// Wait for the cleanup process to complete with a timeout
		select {
		case result := <-resultCh:
			if result.err != nil {
				return fmt.Errorf("unable to finish %v: %s", cmd.Path, result.err)
			}
			return verifyWithLock("", mutex, exec)
		case <-time.After(30 * time.Second):
			// Kill the process if it's still running
			if cmd.Process != nil {
				cmd.Process.Kill()
				// Wait for the goroutine to finish and reap the process
				<-resultCh
			}
			return fmt.Errorf("timeout waiting for cleanup process to finish")
		}
	}, nil
}

// run executes the given command and captures its output for logging and error reporting.
func run(cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to execute %v: %s\n%s", cmd.Path, err, string(out))
	}
	log.Debugf("Command %v output %v", cmd.Path, string(out))
	return nil
}

// verifyUnlocked verifies the system proxy configuration matches the expected value.
// This function assumes the caller already holds the necessary locks and does not
// acquire any locks itself. It queries the system proxy settings and compares them
// to the expected value.
//
// Parameters:
//   - expected: the expected proxy address (empty string for no proxy)
//
// Returns an error if verification fails or if the actual value doesn't match expected.
func verifyUnlocked(expected string) error {
	cmd := be.Command("show")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	actual := string(out)
	log.Debugf("Command %v output %v", cmd.Path, actual)
	if !allEquals(expected, actual) {
		return fmt.Errorf("unexpected output: expect '%s', got '%s'", expected, actual)
	}
	return nil
}

// verifyWithLock verifies the system proxy configuration while safely acquiring
// the provided mutex. This is used by asynchronous operations that need to verify
// the proxy state from goroutines or callbacks.
//
// Parameters:
//   - expected: the expected proxy address (empty string for no proxy)
//   - mutex: the mutex to acquire before accessing shared resources
//   - exec: the byteexec instance to use for executing the verification command
//
// Returns an error if verification fails or if the actual value doesn't match expected.
func verifyWithLock(expected string, mutex *sync.Mutex, exec *byteexec.Exec) error {
	mutex.Lock()
	defer mutex.Unlock()
	cmd := exec.Command("show")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	actual := string(out)
	log.Debugf("Command %v output %v", cmd.Path, actual)
	if !allEquals(expected, actual) {
		return fmt.Errorf("unexpected output: expect '%s', got '%s'", expected, actual)
	}
	return nil
}

// allEquals checks if all non-empty lines in the actual output equal the expected value.
// It handles cases where the output contains multiple lines with the same value or
// empty/whitespace-only lines. Uses XOR logic to ensure both are either empty or non-empty.
//
// Parameters:
//   - expected: the expected proxy address
//   - actual: the actual output from the system proxy query (may contain multiple lines)
//
// Returns true if all non-empty lines match the expected value, false otherwise.
func allEquals(expected string, actual string) bool {
	if (expected == "") != (strings.TrimSpace(actual) == "") { // XOR
		return false
	}
	lines := strings.Split(actual, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && trimmed != expected {
			return false
		}
	}
	return true
}
