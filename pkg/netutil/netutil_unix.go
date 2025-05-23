//go:build unix

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package netutil

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"

	"github.com/go-viper/mapstructure/v2"
	"github.com/vishvananda/netlink"

	"github.com/containerd/log"

	"github.com/containerd/nerdctl/v2/pkg/defaults"
	"github.com/containerd/nerdctl/v2/pkg/rootlessutil"
	"github.com/containerd/nerdctl/v2/pkg/strutil"
	"github.com/containerd/nerdctl/v2/pkg/systemutil"
)

const (
	DefaultNetworkName = "bridge"
	DefaultCIDR        = "172.17.0.0/24"
	DefaultIPAMDriver  = "host-local"

	// When creating non-default network without passing in `--subnet` option,
	// nerdctl assigns subnet address for the creation starting from `StartingCIDR`
	// This prevents subnet address overlapping with `DefaultCIDR` used by the default network
	StartingCIDR = "172.17.1.0/24"
)

func (n *NetworkConfig) subnets() []*net.IPNet {
	var subnets []*net.IPNet
	if len(n.Plugins) > 0 && n.Plugins[0].Network.Type == "bridge" {
		var bridge bridgeConfig
		if err := json.Unmarshal(n.Plugins[0].Bytes, &bridge); err != nil {
			return subnets
		}
		if bridge.IPAM["type"] != "host-local" {
			return subnets
		}
		var ipam hostLocalIPAMConfig
		if err := mapstructure.Decode(bridge.IPAM, &ipam); err != nil {
			return subnets
		}
		for _, irange := range ipam.Ranges {
			if len(irange) > 0 {
				_, subnet, err := net.ParseCIDR(irange[0].Subnet)
				if err != nil {
					continue
				}
				subnets = append(subnets, subnet)
			}
		}
	}
	return subnets
}

func (n *NetworkConfig) clean() error {
	// Remove the bridge network interface on the host.
	if len(n.Plugins) > 0 && n.Plugins[0].Network.Type == "bridge" {
		var bridge bridgeConfig
		if err := json.Unmarshal(n.Plugins[0].Bytes, &bridge); err != nil {
			return err
		}
		return removeBridgeNetworkInterface(bridge.BrName)
	}
	return nil
}

func (e *CNIEnv) generateCNIPlugins(driver string, name string, ipam map[string]interface{}, opts map[string]string, ipv6 bool) ([]CNIPlugin, error) {
	var (
		plugins []CNIPlugin
		err     error
	)
	switch driver {
	case "bridge":
		mtu := 0
		iPMasq := true
		for opt, v := range opts {
			switch opt {
			case "mtu", "com.docker.network.driver.mtu":
				mtu, err = parseMTU(v)
				if err != nil {
					return nil, err
				}
			case "ip-masq", "com.docker.network.bridge.enable_ip_masquerade":
				iPMasq, err = strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("unsupported %q network option %q", driver, opt)
			}
		}
		var bridge *bridgeConfig
		if name == DefaultNetworkName {
			bridge = newBridgePlugin("nerdctl0")
		} else {
			bridge = newBridgePlugin("br-" + networkID(name)[:12])
		}
		bridge.MTU = mtu
		bridge.IPAM = ipam
		bridge.IsGW = true
		bridge.IPMasq = iPMasq
		bridge.HairpinMode = true
		if ipv6 {
			bridge.Capabilities["ips"] = true
		}
		plugins = []CNIPlugin{bridge, newTuningPlugin()}
	case "macvlan", "ipvlan":
		mtu := 0
		mode := ""
		master := ""
		for opt, v := range opts {
			switch opt {
			case "mtu", "com.docker.network.driver.mtu":
				mtu, err = parseMTU(v)
				if err != nil {
					return nil, err
				}
			case "mode", "macvlan_mode", "ipvlan_mode":
				if driver == "macvlan" && opt != "ipvlan_mode" {
					if !strutil.InStringSlice([]string{"bridge"}, v) {
						return nil, fmt.Errorf("unknown macvlan mode %q", v)
					}
				} else if driver == "ipvlan" && opt != "macvlan_mode" {
					if !strutil.InStringSlice([]string{"l2", "l3"}, v) {
						return nil, fmt.Errorf("unknown ipvlan mode %q", v)
					}
				} else {
					return nil, fmt.Errorf("unsupported %q network option %q", driver, opt)
				}
				mode = v
			case "parent":
				master = v
			default:
				return nil, fmt.Errorf("unsupported %q network option %q", driver, opt)
			}
		}
		vlan := newVLANPlugin(driver)
		vlan.MTU = mtu
		vlan.Master = master
		vlan.Mode = mode
		vlan.IPAM = ipam
		if ipv6 {
			vlan.Capabilities["ips"] = true
		}
		plugins = []CNIPlugin{vlan}
	default:
		return nil, fmt.Errorf("unsupported cni driver %q", driver)
	}
	return plugins, nil
}

func (e *CNIEnv) generateIPAM(driver string, subnets []string, gatewayStr, ipRangeStr string, opts map[string]string, ipv6 bool) (map[string]interface{}, error) {
	var ipamConfig interface{}
	switch driver {
	case "default", "host-local":
		ipamConf := newHostLocalIPAMConfig()
		ipamConf.Routes = []IPAMRoute{
			{Dst: "0.0.0.0/0"},
		}
		ranges, findIPv4, err := e.parseIPAMRanges(subnets, gatewayStr, ipRangeStr, ipv6)
		if err != nil {
			return nil, err
		}
		ipamConf.Ranges = append(ipamConf.Ranges, ranges...)
		if !findIPv4 {
			ranges, _, _ = e.parseIPAMRanges([]string{""}, gatewayStr, ipRangeStr, ipv6)
			ipamConf.Ranges = append(ipamConf.Ranges, ranges...)
		}
		ipamConfig = ipamConf
	case "dhcp":
		ipamConf := newDHCPIPAMConfig()
		crd, err := defaults.CNIRuntimeDir()
		if err != nil {
			return nil, err
		}
		ipamConf.DaemonSocketPath = filepath.Join(crd, "dhcp.sock")
		if err := systemutil.IsSocketAccessible(ipamConf.DaemonSocketPath); err != nil {
			log.L.Warnf("cannot access dhcp socket %q (hint: try running with `dhcp daemon --socketpath=%s &` in CNI_PATH to launch the dhcp daemon)", ipamConf.DaemonSocketPath, ipamConf.DaemonSocketPath)
		}

		// Set the host-name option to the value of passed argument NERDCTL_CNI_DHCP_HOSTNAME
		opts["host-name"] = `{"type": "provide", "fromArg": "NERDCTL_CNI_DHCP_HOSTNAME"}`

		// Convert all user-defined ipam-options into serializable options
		for optName, optValue := range opts {
			parsed := &struct {
				Type            string `json:"type"`
				Value           string `json:"value"`
				ValueFromCNIArg string `json:"fromArg"`
				SkipDefault     bool   `json:"skipDefault"`
			}{}
			if err := json.Unmarshal([]byte(optValue), parsed); err != nil {
				return nil, fmt.Errorf("unparsable ipam option %s %q", optName, optValue)
			}
			if parsed.Type == "provide" {
				ipamConf.ProvideOptions = append(ipamConf.ProvideOptions, provideOption{
					Option:          optName,
					Value:           parsed.Value,
					ValueFromCNIArg: parsed.ValueFromCNIArg,
				})
			} else if parsed.Type == "request" {
				ipamConf.RequestOptions = append(ipamConf.RequestOptions, requestOption{
					Option:      optName,
					SkipDefault: parsed.SkipDefault,
				})
			} else {
				return nil, fmt.Errorf("ipam option must have a type (provide or request)")
			}
		}

		ipamConfig = ipamConf
	default:
		return nil, fmt.Errorf("unsupported ipam driver %q", driver)
	}

	ipam, err := structToMap(ipamConfig)
	if err != nil {
		return nil, err
	}
	return ipam, nil
}

func (e *CNIEnv) parseIPAMRanges(subnets []string, gateway, ipRange string, ipv6 bool) ([][]IPAMRange, bool, error) {
	findIPv4 := false
	ranges := make([][]IPAMRange, 0, len(subnets))
	for i := range subnets {
		subnet, err := e.parseSubnet(subnets[i])
		if err != nil {
			return nil, findIPv4, err
		}
		// if ipv6 flag is not set, subnets of ipv6 should be excluded
		if !ipv6 && subnet.IP.To4() == nil {
			continue
		}
		if !findIPv4 && subnet.IP.To4() != nil {
			findIPv4 = true
		}
		ipamRange, err := parseIPAMRange(subnet, gateway, ipRange)
		if err != nil {
			return nil, findIPv4, err
		}
		ranges = append(ranges, []IPAMRange{*ipamRange})
	}
	return ranges, findIPv4, nil
}

func removeBridgeNetworkInterface(netIf string) error {
	return rootlessutil.WithDetachedNetNSIfAny(func() error {
		link, err := netlink.LinkByName(netIf)
		if err == nil {
			if err := netlink.LinkDel(link); err != nil {
				return fmt.Errorf("failed to remove network interface %s: %v", netIf, err)
			}
		}
		return nil
	})
}
