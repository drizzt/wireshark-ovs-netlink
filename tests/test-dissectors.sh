#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test suite for the OVS Netlink dissector plugin.
#
# Validates that tshark correctly decodes OVS generic netlink families
# (ovs_vport, ovs_datapath, ovs_flow) from a reference pcap capture.
#
# Usage: test-dissectors.sh <tshark> <pcap>

set -euo pipefail

TSHARK="${1:?Usage: $0 <tshark> <pcap>}"
PCAP="${2:?Usage: $0 <tshark> <pcap>}"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    if "$@"; then
        echo "  PASS  $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $name"
        FAIL=$((FAIL + 1))
    fi
}

# Helper: check that a display filter matches at least one packet
filter_has_packets() {
    local filter="$1"
    local count
    count=$("$TSHARK" -r "$PCAP" -Y "$filter" 2>/dev/null | wc -l)
    [ "$count" -gt 0 ]
}

# Helper: check that a field value appears in tshark output
field_contains() {
    local filter="$1"
    local field="$2"
    local expected="$3"
    "$TSHARK" -r "$PCAP" -Y "$filter" -T fields -e "$field" 2>/dev/null \
        | grep -qF "$expected"
}

# Helper: check that the protocol column shows the expected protocol
protocol_column_shows() {
    local filter="$1"
    local expected="$2"
    "$TSHARK" -r "$PCAP" -Y "$filter" -T fields -e _ws.col.Protocol 2>/dev/null \
        | grep -qF "$expected"
}

echo "Running OVS Netlink dissector tests..."
echo "  tshark: $TSHARK"
echo "  pcap:   $PCAP"
echo ""

# --- ovs_vport ---
run_test "vport_filter"   filter_has_packets "ovs_vport"
run_test "vport_cmd"      field_contains "ovs_vport" "ovs_vport.cmd" "3"
run_test "vport_name"     field_contains "ovs_vport.name" "ovs_vport.name" "ovs-system"
run_test "vport_port_no"  field_contains "ovs_vport.port_no" "ovs_vport.port_no" "0"
run_test "vport_type"     field_contains "ovs_vport.type" "ovs_vport.type" "2"
run_test "vport_protocol" protocol_column_shows "ovs_vport" "ovs_vport"

# --- ovs_datapath ---
run_test "datapath_filter"   filter_has_packets "ovs_datapath"
run_test "datapath_name"     field_contains "ovs_datapath.name" "ovs_datapath.name" "ovs-system"
run_test "datapath_stats"    field_contains "ovs_datapath.stats.n_flows" "ovs_datapath.stats.n_flows" "0"
run_test "datapath_cache"    field_contains "ovs_datapath.masks_cache_size" "ovs_datapath.masks_cache_size" "256"
run_test "datapath_protocol" protocol_column_shows "ovs_datapath" "ovs_datapath"

# --- ovs_flow ---
run_test "flow_filter"   filter_has_packets "ovs_flow"
run_test "flow_cmd"      field_contains "ovs_flow" "ovs_flow.cmd" "3"
run_test "flow_protocol" protocol_column_shows "ovs_flow" "ovs_flow"

echo ""
echo "Results: $PASS passed, $FAIL failed (out of $((PASS + FAIL)))"

[ "$FAIL" -eq 0 ]
