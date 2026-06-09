// Package sysproxy provides macOS-specific implementation for system proxy management.
// This file adds Automatic Proxy Configuration (PAC), Auto Proxy Discovery (WPAD),
// and manual web/secure-web proxy management for a given network service.
//
// Unlike On/Off/bypass — which route through the embedded setuid helper so a
// non-root caller can still change the system proxy — these functions drive the
// macOS `networksetup` tool directly. They are intended for callers that already
// run with sufficient privileges (e.g. a root LaunchDaemon); networksetup writes
// require root, while reads do not.
package sysproxy

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// networkSetupBin is the macOS CLI used to read and write per-network-service
// proxy configuration.
const networkSetupBin = "/usr/sbin/networksetup"

// networksetup verbs for the auto-proxy (PAC), auto-proxy-discovery (WPAD), and
// manual web/secure proxy settings.
const (
	verbGetAutoProxyURL        = "-getautoproxyurl"
	verbSetAutoProxyURL        = "-setautoproxyurl"
	verbSetAutoProxyState      = "-setautoproxystate"
	verbGetProxyAutoDiscovery  = "-getproxyautodiscovery"
	verbSetProxyAutoDiscovery  = "-setproxyautodiscovery"
	verbGetWebProxy            = "-getwebproxy"
	verbSetWebProxy            = "-setwebproxy"
	verbSetWebProxyState       = "-setwebproxystate"
	verbGetSecureWebProxy      = "-getsecurewebproxy"
	verbSetSecureWebProxy      = "-setsecurewebproxy"
	verbSetSecureWebProxyState = "-setsecurewebproxystate"
)

// nullURL is the placeholder networksetup prints for an unset PAC URL.
const nullURL = "(null)"

// AutoProxyConfig is a network service's Automatic Proxy Configuration (PAC):
// the script URL and whether macOS is currently honouring it.
type AutoProxyConfig struct {
	URL     string
	Enabled bool
}

// WebProxyConfig is a network service's manual web or secure-web proxy: the
// host, port, and whether macOS is currently honouring it.
type WebProxyConfig struct {
	Host    string
	Port    string
	Enabled bool
}

// ListNetworkServices returns the names of all enabled network services
// (e.g. "Wi-Fi", "Thunderbolt Ethernet"). The informational header line and
// disabled services (which networksetup prefixes with "*") are skipped, since a
// disabled service carries no live proxy traffic.
//
// Returns the service names and any error encountered while listing them.
func ListNetworkServices() ([]string, error) {
	out, err := runNetworkSetup("-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip blanks, the "An asterisk (*) denotes..." header, and any
		// "*"-prefixed (disabled) service.
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

// onOff maps a boolean to the on/off literal networksetup expects.
//
// Parameters:
//   - on: the desired state.
//
// Returns "on" when on is true, "off" otherwise.
func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// runNetworkSetup executes networksetup with the given arguments and returns its
// combined stdout. The command output is needed for the read verbs, so failures
// include the captured output for diagnosis.
//
// Parameters:
//   - args: the networksetup arguments (verb first, then service and values).
//
// Returns the command output and any error encountered while running it.
func runNetworkSetup(args ...string) (string, error) {
	out, err := exec.Command(networkSetupBin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("networksetup %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// fieldAfterColon returns the trimmed value following the first colon on the
// line whose text (before the colon) equals key, scanning output line by line.
//
// Parameters:
//   - output: the multi-line networksetup output.
//   - key:    the field label to match (e.g. "URL", "Server").
//
// Returns the field value, or "" when the key is absent.
func fieldAfterColon(output, key string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// isEnabledWord reports whether a networksetup state word means "enabled".
// networksetup spells the state as "Yes" for proxies and "On" for discovery.
//
// Parameters:
//   - v: the state word to interpret.
func isEnabledWord(v string) bool {
	return strings.EqualFold(v, "Yes") || strings.EqualFold(v, "On")
}

// GetAutoProxy reads the Automatic Proxy Configuration (PAC) for a network
// service: the script URL and whether it is enabled.
//
// Parameters:
//   - service: the network service identifier (e.g. "Wi-Fi", "Ethernet").
//
// Returns the PAC configuration and any error encountered while reading it. An
// unset URL ("(null)") is normalized to "".
func GetAutoProxy(service string) (AutoProxyConfig, error) {
	var cfg AutoProxyConfig
	out, err := runNetworkSetup(verbGetAutoProxyURL, service)
	if err != nil {
		return cfg, err
	}
	if url := fieldAfterColon(out, "URL"); url != nullURL {
		cfg.URL = url
	}
	cfg.Enabled = isEnabledWord(fieldAfterColon(out, "Enabled"))
	return cfg, nil
}

// SetAutoProxyURL sets the Automatic Proxy Configuration (PAC) URL for a network
// service. networksetup enables the PAC as a side effect of setting the URL.
//
// Parameters:
//   - service: the network service identifier.
//   - url:     the PAC script URL.
//
// Returns any error encountered while writing the setting.
func SetAutoProxyURL(service, url string) error {
	_, err := runNetworkSetup(verbSetAutoProxyURL, service, url)
	return err
}

// SetAutoProxyState enables or disables the Automatic Proxy Configuration (PAC)
// for a network service without changing its configured URL.
//
// Parameters:
//   - service: the network service identifier.
//   - on:      true to enable the PAC, false to disable it.
//
// Returns any error encountered while writing the setting.
func SetAutoProxyState(service string, on bool) error {
	_, err := runNetworkSetup(verbSetAutoProxyState, service, onOff(on))
	return err
}

// GetProxyAutoDiscovery reports whether Auto Proxy Discovery (WPAD) is enabled
// for a network service.
//
// Parameters:
//   - service: the network service identifier.
//
// Returns the enabled state and any error encountered while reading it.
func GetProxyAutoDiscovery(service string) (bool, error) {
	out, err := runNetworkSetup(verbGetProxyAutoDiscovery, service)
	if err != nil {
		return false, err
	}
	// networksetup prints either a bare "On"/"Off" or "<label>: On" depending on
	// the OS version; handle both by checking for the state word anywhere.
	if v := fieldAfterColon(out, "Auto Proxy Discovery"); v != "" {
		return isEnabledWord(v), nil
	}
	return isEnabledWord(strings.TrimSpace(out)), nil
}

// SetProxyAutoDiscovery enables or disables Auto Proxy Discovery (WPAD) for a
// network service.
//
// Parameters:
//   - service: the network service identifier.
//   - on:      true to enable WPAD, false to disable it.
//
// Returns any error encountered while writing the setting.
func SetProxyAutoDiscovery(service string, on bool) error {
	_, err := runNetworkSetup(verbSetProxyAutoDiscovery, service, onOff(on))
	return err
}

// GetWebProxy reads the manual web (HTTP) proxy for a network service.
//
// Parameters:
//   - service: the network service identifier.
//
// Returns the web proxy configuration and any error encountered while reading it.
func GetWebProxy(service string) (WebProxyConfig, error) {
	return getWebProxy(verbGetWebProxy, service)
}

// GetSecureWebProxy reads the manual secure-web (HTTPS) proxy for a network
// service.
//
// Parameters:
//   - service: the network service identifier.
//
// Returns the secure-web proxy configuration and any error encountered while
// reading it.
func GetSecureWebProxy(service string) (WebProxyConfig, error) {
	return getWebProxy(verbGetSecureWebProxy, service)
}

// getWebProxy reads a manual proxy (web or secure-web) for a network service and
// parses the shared "Enabled/Server/Port" networksetup output shape.
//
// Parameters:
//   - verb:    the networksetup read verb (web or secure-web).
//   - service: the network service identifier.
//
// Returns the parsed proxy configuration and any error encountered while reading.
func getWebProxy(verb, service string) (WebProxyConfig, error) {
	var cfg WebProxyConfig
	out, err := runNetworkSetup(verb, service)
	if err != nil {
		return cfg, err
	}
	cfg.Enabled = isEnabledWord(fieldAfterColon(out, "Enabled"))
	cfg.Host = fieldAfterColon(out, "Server")
	cfg.Port = fieldAfterColon(out, "Port")
	return cfg, nil
}

// SetWebProxy sets the manual web (HTTP) proxy host and port for a network
// service. networksetup enables the web proxy as a side effect.
//
// Parameters:
//   - service: the network service identifier.
//   - host:    the proxy host.
//   - port:    the proxy port.
//
// Returns any error encountered while writing the setting.
func SetWebProxy(service, host, port string) error {
	_, err := runNetworkSetup(verbSetWebProxy, service, host, port)
	return err
}

// SetWebProxyState enables or disables the manual web (HTTP) proxy for a network
// service without changing its configured host/port.
//
// Parameters:
//   - service: the network service identifier.
//   - on:      true to enable the web proxy, false to disable it.
//
// Returns any error encountered while writing the setting.
func SetWebProxyState(service string, on bool) error {
	_, err := runNetworkSetup(verbSetWebProxyState, service, onOff(on))
	return err
}

// SetSecureWebProxy sets the manual secure-web (HTTPS) proxy host and port for a
// network service. networksetup enables the secure-web proxy as a side effect.
//
// Parameters:
//   - service: the network service identifier.
//   - host:    the proxy host.
//   - port:    the proxy port.
//
// Returns any error encountered while writing the setting.
func SetSecureWebProxy(service, host, port string) error {
	_, err := runNetworkSetup(verbSetSecureWebProxy, service, host, port)
	return err
}

// SetSecureWebProxyState enables or disables the manual secure-web (HTTPS) proxy
// for a network service without changing its configured host/port.
//
// Parameters:
//   - service: the network service identifier.
//   - on:      true to enable the secure-web proxy, false to disable it.
//
// Returns any error encountered while writing the setting.
func SetSecureWebProxyState(service string, on bool) error {
	_, err := runNetworkSetup(verbSetSecureWebProxyState, service, onOff(on))
	return err
}
