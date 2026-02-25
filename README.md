# wireshark-ovs-netlink

An out-of-tree Wireshark dissector plugin for Open vSwitch generic netlink
protocols. It decodes the kernel-to-userspace netlink messages that OVS uses
to manage datapaths, virtual ports, flows, packets, meters, and connection
tracking limits.

## Supported protocols

| Filter name    | Description                                         |
|----------------|-----------------------------------------------------|
| `ovs_vport`    | Virtual port management (create/delete/get/set)     |
| `ovs_datapath` | Datapath management and statistics                  |
| `ovs_flow`     | Flow table operations (keys, actions, masks, UFIDs) |
| `ovs_packet`   | Upcall and execute packet operations                |
| `ovs_meter`    | Meter configuration and band statistics             |
| `ovs_ct_limit` | Connection tracking zone limits                     |

Each dissector fully decodes the genl header (command, version), the
OVS-specific header (datapath ifindex), and all nested netlink attributes
defined in `<linux/openvswitch.h>`.

## Requirements

- Wireshark 4.6+ (built with plugin support and development headers installed)
- CMake 3.16+
- A C11 compiler (GCC or Clang)

On Fedora/RHEL:

```
sudo dnf install wireshark-devel cmake gcc
```

On Debian/Ubuntu:

```
sudo apt install wireshark-dev cmake gcc
```

## Building

```
mkdir build && cd build
cmake ..
make
```

## Installation

Install to the system Wireshark plugin directory:

```
sudo make install
```

Or install to your personal plugin directory (no root required):

```
make copy_plugin
```

This copies the built `ovs_netlink.so` to
`~/.local/lib/wireshark/plugins/<version>/epan/`.

## Capturing OVS netlink traffic

OVS communicates with the kernel via generic netlink sockets. To capture this
traffic you need a `nlmon` interface:

```
sudo modprobe nlmon
sudo ip link add nlmon0 type nlmon
sudo ip link set nlmon0 up
```

Then capture with Wireshark or tshark:

```
sudo tshark -i nlmon0 -w ovs-capture.pcap
```

In another terminal, generate OVS traffic:

```
sudo ovs-vsctl show
sudo ovs-dpctl dump-flows
```

Stop the capture and open the pcap. The plugin will automatically decode any
OVS generic netlink messages.

To clean up the nlmon interface:

```
sudo ip link del nlmon0
```

## Display filter examples

```
ovs_vport                            # all vport messages
ovs_vport.name == "br0"              # vport operations on bridge br0
ovs_datapath.stats.n_flows > 0       # datapaths with active flows
ovs_flow.key.ipv4_dst == 10.0.0.1    # flows matching a destination IP
ovs_flow.cmd == 1                    # OVS_FLOW_CMD_NEW operations
ovs_meter.id == 1                    # meter ID 1
```

## Running tests

The test suite uses tshark to validate field decoding against a reference
pcap capture. tshark must be installed and the plugin must be built first:

```
cd build
cmake ..
make
make copy_plugin   # install so tshark can load it
ctest --verbose
```

## Project structure

```
CMakeLists.txt                         # Build system
src/
  plugin.c                             # Plugin entry point and registration
  netlink-helpers.c                    # Netlink attribute parsing (reimplements
  netlink-helpers.h                    #   unexported libwireshark internals)
  packet-netlink-ovs_vport.c           # ovs_vport dissector
  packet-netlink-ovs_datapath.c        # ovs_datapath dissector
  packet-netlink-ovs_flow.c            # ovs_flow dissector
  packet-netlink-ovs_packet.c          # ovs_packet dissector
  packet-netlink-ovs_meter.c           # ovs_meter dissector
  packet-netlink-ovs_ct_limit.c        # ovs_ct_limit dissector
tests/
  test-dissectors.sh                   # Test script (used by ctest)
  ovs-netlink.pcap                     # Reference capture
```

## License

GPL-2.0-or-later (same as Wireshark).
