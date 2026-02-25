/* netlink-helpers.h
 * Self-contained netlink attribute parsing helpers for out-of-tree plugins.
 * These reimplement the functionality of dissect_netlink_attributes() and
 * dissect_genl_header() which are not exported from libwireshark.
 *
 * Copyright 2025, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __OVS_NETLINK_HELPERS_H__
#define __OVS_NETLINK_HELPERS_H__

#include "compat.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-netlink.h>

/* Register hf/ett fields used by the helpers. Must be called once. */
void ovs_netlink_helpers_register(void);

/* Parse the genlmsghdr (4 bytes: cmd + version + reserved) */
int ovs_dissect_genl_header(tvbuff_t *tvb, genl_info_t *genl_info,
    struct packet_netlink_data *nl_data, int hf_cmd);

/* Parse netlink attributes within a bounded length */
int ovs_dissect_netlink_attributes(tvbuff_t *tvb, int hf_type, int ett,
    void *data, struct packet_netlink_data *nl_data, proto_tree *tree,
    int offset, int length, netlink_attributes_cb_t cb);

/* Parse netlink attributes to end of tvb */
int ovs_dissect_netlink_attributes_to_end(tvbuff_t *tvb, int hf_type,
    int ett, void *data, struct packet_netlink_data *nl_data,
    proto_tree *tree, int offset, netlink_attributes_cb_t cb);

/* Parse netlink attribute arrays (nested two-level) */
int ovs_dissect_netlink_attributes_array(tvbuff_t *tvb, int hf_type,
    int ett_array, int ett_attrib, void *data,
    struct packet_netlink_data *nl_data, proto_tree *tree,
    int offset, int length, netlink_attributes_cb_t cb);

#endif /* __OVS_NETLINK_HELPERS_H__ */
