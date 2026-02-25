/* packet-netlink-ovs_vport.c
 * Routines for netlink-ovs_vport dissection
 * Copyright 2025, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ovs_vport manages Open vSwitch virtual ports via Generic Netlink.
 * Each vport is bound to a datapath and has a type (netdev, internal,
 * GRE, VXLAN, Geneve), a port number, and optional tunnel options.
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/openvswitch.h
 */

#include <wireshark.h>

#include <epan/packet.h>


#include <epan/dissectors/packet-netlink.h>

#include "netlink-helpers.h"

void proto_register_netlink_ovs_vport(void);
void proto_reg_handoff_netlink_ovs_vport(void);

/* from <include/uapi/linux/openvswitch.h> prefixed with WS_ */
enum ws_ovs_vport_cmd {
    WS_OVS_VPORT_CMD_UNSPEC,
    WS_OVS_VPORT_CMD_NEW,
    WS_OVS_VPORT_CMD_DEL,
    WS_OVS_VPORT_CMD_GET,
    WS_OVS_VPORT_CMD_SET,
};

enum ws_ovs_vport_type {
    WS_OVS_VPORT_TYPE_UNSPEC,
    WS_OVS_VPORT_TYPE_NETDEV,
    WS_OVS_VPORT_TYPE_INTERNAL,
    WS_OVS_VPORT_TYPE_GRE,
    WS_OVS_VPORT_TYPE_VXLAN,
    WS_OVS_VPORT_TYPE_GENEVE,
};

enum ws_ovs_vport_attr {
    WS_OVS_VPORT_ATTR_UNSPEC,
    WS_OVS_VPORT_ATTR_PORT_NO,
    WS_OVS_VPORT_ATTR_TYPE,
    WS_OVS_VPORT_ATTR_NAME,
    WS_OVS_VPORT_ATTR_OPTIONS,
    WS_OVS_VPORT_ATTR_UPCALL_PID,
    WS_OVS_VPORT_ATTR_STATS,
    WS_OVS_VPORT_ATTR_PAD,
    WS_OVS_VPORT_ATTR_IFINDEX,
    WS_OVS_VPORT_ATTR_NETNSID,
    WS_OVS_VPORT_ATTR_UPCALL_STATS,
};

enum ws_ovs_tunnel_attr {
    WS_OVS_TUNNEL_ATTR_UNSPEC,
    WS_OVS_TUNNEL_ATTR_DST_PORT,
    WS_OVS_TUNNEL_ATTR_EXTENSION,
};

enum ws_ovs_vxlan_ext {
    WS_OVS_VXLAN_EXT_UNSPEC,
    WS_OVS_VXLAN_EXT_GBP,
};

enum ws_ovs_vport_upcall_attr {
    WS_OVS_VPORT_UPCALL_ATTR_SUCCESS,
    WS_OVS_VPORT_UPCALL_ATTR_FAIL,
};

static const value_string ws_ovs_vport_commands_vals[] = {
    { WS_OVS_VPORT_CMD_UNSPEC,      "OVS_VPORT_CMD_UNSPEC" },
    { WS_OVS_VPORT_CMD_NEW, "OVS_VPORT_CMD_NEW" },
    { WS_OVS_VPORT_CMD_DEL, "OVS_VPORT_CMD_DEL" },
    { WS_OVS_VPORT_CMD_GET, "OVS_VPORT_CMD_GET" },
    { WS_OVS_VPORT_CMD_SET, "OVS_VPORT_CMD_SET" },
    { 0, NULL }
};

static const value_string ws_ovs_vport_type_vals[] = {
    { WS_OVS_VPORT_TYPE_UNSPEC,     "OVS_VPORT_TYPE_UNSPEC" },
    { WS_OVS_VPORT_TYPE_NETDEV,     "OVS_VPORT_TYPE_NETDEV" },
    { WS_OVS_VPORT_TYPE_INTERNAL,   "OVS_VPORT_TYPE_INTERNAL" },
    { WS_OVS_VPORT_TYPE_GRE,        "OVS_VPORT_TYPE_GRE" },
    { WS_OVS_VPORT_TYPE_VXLAN,      "OVS_VPORT_TYPE_VXLAN" },
    { WS_OVS_VPORT_TYPE_GENEVE,     "OVS_VPORT_TYPE_GENEVE" },
    { 0, NULL }
};

static const value_string ws_ovs_vport_attr_vals[] = {
    { WS_OVS_VPORT_ATTR_UNSPEC,             "OVS_VPORT_ATTR_UNSPEC" },
    { WS_OVS_VPORT_ATTR_PORT_NO,            "OVS_VPORT_ATTR_PORT_NO" },
    { WS_OVS_VPORT_ATTR_TYPE,               "OVS_VPORT_ATTR_TYPE" },
    { WS_OVS_VPORT_ATTR_NAME,               "OVS_VPORT_ATTR_NAME" },
    { WS_OVS_VPORT_ATTR_OPTIONS,            "OVS_VPORT_ATTR_OPTIONS" },
    { WS_OVS_VPORT_ATTR_UPCALL_PID, "OVS_VPORT_ATTR_UPCALL_PID" },
    { WS_OVS_VPORT_ATTR_STATS,              "OVS_VPORT_ATTR_STATS" },
    { WS_OVS_VPORT_ATTR_PAD,                "OVS_VPORT_ATTR_PAD" },
    { WS_OVS_VPORT_ATTR_IFINDEX,            "OVS_VPORT_ATTR_IFINDEX" },
    { WS_OVS_VPORT_ATTR_NETNSID,            "OVS_VPORT_ATTR_NETNSID" },
    { WS_OVS_VPORT_ATTR_UPCALL_STATS,       "OVS_VPORT_ATTR_UPCALL_STATS" },
    { 0, NULL }
};

static const value_string ws_ovs_tunnel_attr_vals[] = {
    { WS_OVS_TUNNEL_ATTR_UNSPEC,            "OVS_TUNNEL_ATTR_UNSPEC" },
    { WS_OVS_TUNNEL_ATTR_DST_PORT,          "OVS_TUNNEL_ATTR_DST_PORT" },
    { WS_OVS_TUNNEL_ATTR_EXTENSION, "OVS_TUNNEL_ATTR_EXTENSION" },
    { 0, NULL }
};

static const value_string ws_ovs_vxlan_ext_vals[] = {
    { WS_OVS_VXLAN_EXT_UNSPEC,      "OVS_VXLAN_EXT_UNSPEC" },
    { WS_OVS_VXLAN_EXT_GBP, "OVS_VXLAN_EXT_GBP" },
    { 0, NULL }
};

static const value_string ws_ovs_vport_upcall_attr_vals[] = {
    { WS_OVS_VPORT_UPCALL_ATTR_SUCCESS,     "OVS_VPORT_UPCALL_ATTR_SUCCESS" },
    { WS_OVS_VPORT_UPCALL_ATTR_FAIL,        "OVS_VPORT_UPCALL_ATTR_FAIL" },
    { 0, NULL }
};

struct netlink_ovs_vport_info {
    packet_info *pinfo;
};

static dissector_handle_t netlink_ovs_vport_handle;

static int proto_netlink_ovs_vport;

static int hf_ovs_vport_commands;
static int hf_ovs_vport_dp_ifindex;
static int hf_ovs_vport_attr;
static int hf_ovs_vport_port_no;
static int hf_ovs_vport_type;
static int hf_ovs_vport_name;
static int hf_ovs_vport_upcall_pid;
static int hf_ovs_vport_ifindex;
static int hf_ovs_vport_netnsid;
static int hf_ovs_vport_stats_rx_packets;
static int hf_ovs_vport_stats_tx_packets;
static int hf_ovs_vport_stats_rx_bytes;
static int hf_ovs_vport_stats_tx_bytes;
static int hf_ovs_vport_stats_rx_errors;
static int hf_ovs_vport_stats_tx_errors;
static int hf_ovs_vport_stats_rx_dropped;
static int hf_ovs_vport_stats_tx_dropped;
static int hf_ovs_vport_tunnel_attr;
static int hf_ovs_vport_tunnel_dst_port;
static int hf_ovs_vport_vxlan_ext_attr;
static int hf_ovs_vport_vxlan_ext_gbp;
static int hf_ovs_vport_upcall_stats_attr;
static int hf_ovs_vport_upcall_success;
static int hf_ovs_vport_upcall_fail;

static int ett_ovs_vport = -1;
static int ett_ovs_vport_attrs = -1;
static int ett_ovs_vport_stats = -1;
static int ett_ovs_vport_tunnel_attrs = -1;
static int ett_ovs_vport_vxlan_ext_attrs = -1;
static int ett_ovs_vport_upcall_stats_attrs = -1;

static int
dissect_ovs_vport_vxlan_ext_attrs(tvbuff_t *tvb, void *data _U_,
    struct packet_netlink_data *nl_data, proto_tree *tree,
    int nla_type, int offset, int len)
{
    enum ws_ovs_vxlan_ext type = (enum ws_ovs_vxlan_ext) nla_type;

    switch (type) {
    case WS_OVS_VXLAN_EXT_GBP:
        proto_tree_add_item(tree, hf_ovs_vport_vxlan_ext_gbp, tvb,
            offset, len, nl_data->encoding);
        return 1;
    default:
        return 0;
    }
}

static int
dissect_ovs_vport_tunnel_attrs(tvbuff_t *tvb, void *data,
    struct packet_netlink_data *nl_data, proto_tree *tree,
    int nla_type, int offset, int len)
{
    enum ws_ovs_tunnel_attr type = (enum ws_ovs_tunnel_attr) nla_type;

    switch (type) {
    case WS_OVS_TUNNEL_ATTR_DST_PORT:
        proto_tree_add_item(tree, hf_ovs_vport_tunnel_dst_port, tvb,
            offset, 2, nl_data->encoding);
        return 1;
    case WS_OVS_TUNNEL_ATTR_EXTENSION:
        return ovs_dissect_netlink_attributes(tvb,
            hf_ovs_vport_vxlan_ext_attr,
            ett_ovs_vport_vxlan_ext_attrs, data, nl_data,
            tree, offset, len,
            dissect_ovs_vport_vxlan_ext_attrs);
    default:
        return 0;
    }
}

static int
dissect_ovs_vport_upcall_stats_attrs(tvbuff_t *tvb, void *data _U_,
    struct packet_netlink_data *nl_data, proto_tree *tree,
    int nla_type, int offset, int len _U_)
{
    enum ws_ovs_vport_upcall_attr type =
        (enum ws_ovs_vport_upcall_attr) nla_type;

    switch (type) {
    case WS_OVS_VPORT_UPCALL_ATTR_SUCCESS:
        proto_tree_add_item(tree, hf_ovs_vport_upcall_success, tvb,
            offset, 8, nl_data->encoding);
        return 1;
    case WS_OVS_VPORT_UPCALL_ATTR_FAIL:
        proto_tree_add_item(tree, hf_ovs_vport_upcall_fail, tvb,
            offset, 8, nl_data->encoding);
        return 1;
    default:
        return 0;
    }
}

static int
dissect_ovs_vport_attrs(tvbuff_t *tvb, void *data,
    struct packet_netlink_data *nl_data, proto_tree *tree,
    int nla_type, int offset, int len)
{
    enum ws_ovs_vport_attr type = (enum ws_ovs_vport_attr) nla_type;
    uint32_t value;
    const uint8_t *str;
    proto_item *pi;
    proto_tree *ptree;

    switch (type) {
    case WS_OVS_VPORT_ATTR_PORT_NO:
        proto_tree_add_item_ret_uint(tree, hf_ovs_vport_port_no, tvb,
            offset, 4, nl_data->encoding, &value);
        proto_item_append_text(tree, ": %u", value);
        return 1;

    case WS_OVS_VPORT_ATTR_TYPE:
        {
            struct netlink_ovs_vport_info *info =
                (struct netlink_ovs_vport_info *) data;
            proto_tree_add_item_ret_uint(tree, hf_ovs_vport_type,
                tvb, offset, 4, nl_data->encoding, &value);
            proto_item_append_text(tree, ": %s",
                ovs_val_to_str(info->pinfo->pool, value,
                    ws_ovs_vport_type_vals,
                    "Unknown (%u)"));
        }
        return 1;

    case WS_OVS_VPORT_ATTR_NAME:
        {
            struct netlink_ovs_vport_info *info =
                (struct netlink_ovs_vport_info *) data;
            proto_tree_add_item_ret_string(tree,
                hf_ovs_vport_name, tvb,
                offset, len, ENC_ASCII | ENC_NA,
                info->pinfo->pool, &str);
            proto_item_append_text(tree, ": %s", str);
        }
        return 1;

    case WS_OVS_VPORT_ATTR_OPTIONS:
        return ovs_dissect_netlink_attributes(tvb,
            hf_ovs_vport_tunnel_attr,
            ett_ovs_vport_tunnel_attrs, data, nl_data,
            tree, offset, len,
            dissect_ovs_vport_tunnel_attrs);

    case WS_OVS_VPORT_ATTR_UPCALL_PID:
        /* Array of u32 PIDs, one per CPU */
        {
            int i;
            for (i = 0; i + 4 <= len; i += 4) {
                proto_tree_add_item(tree,
                    hf_ovs_vport_upcall_pid, tvb,
                    offset + i, 4, nl_data->encoding);
            }
        }
        return 1;

    case WS_OVS_VPORT_ATTR_STATS:
        /* struct ovs_vport_stats: 8 x u64 counters = 64 bytes */
        if (len == 64) {
            int off = offset;
            pi = proto_tree_add_subtree_format(tree, tvb, offset,
                len, 0, &pi, "Vport Statistics");
            ptree = proto_item_add_subtree(pi, ett_ovs_vport_stats);
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_rx_packets, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_tx_packets, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_rx_bytes, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_tx_bytes, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_rx_errors, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_tx_errors, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_rx_dropped, tvb, off, 8,
                nl_data->encoding);
            off += 8;
            proto_tree_add_item(ptree,
                hf_ovs_vport_stats_tx_dropped, tvb, off, 8,
                nl_data->encoding);
        }
        return 1;

    case WS_OVS_VPORT_ATTR_IFINDEX:
        proto_tree_add_item_ret_uint(tree, hf_ovs_vport_ifindex, tvb,
            offset, 4, nl_data->encoding, &value);
        proto_item_append_text(tree, ": %u", value);
        return 1;

    case WS_OVS_VPORT_ATTR_NETNSID:
        proto_tree_add_item_ret_uint(tree, hf_ovs_vport_netnsid, tvb,
            offset, 4, nl_data->encoding, &value);
        proto_item_append_text(tree, ": %u", value);
        return 1;

    case WS_OVS_VPORT_ATTR_UPCALL_STATS:
        return ovs_dissect_netlink_attributes(tvb,
            hf_ovs_vport_upcall_stats_attr,
            ett_ovs_vport_upcall_stats_attrs, data, nl_data,
            tree, offset, len,
            dissect_ovs_vport_upcall_stats_attrs);

    default:
        return 0;
    }
}

static int
dissect_netlink_ovs_vport(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data)
{
    genl_info_t *genl_info = (genl_info_t *) data;
    proto_tree *nlmsg_tree;
    proto_item *pi;
    int offset;

    if (!genl_info) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ovs_vport");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Dissect genlmsghdr (cmd, version, reserved) */
    offset = ovs_dissect_genl_header(tvb, genl_info, genl_info->nl_data,
        hf_ovs_vport_commands);

    /* Dissect ovs_header (dp_ifindex) */
    if (tvb_reported_length_remaining(tvb, offset) < 4)
        return offset;

    pi = proto_tree_add_item(tree, proto_netlink_ovs_vport, tvb, offset,
        -1, ENC_NA);
    nlmsg_tree = proto_item_add_subtree(pi, ett_ovs_vport);

    proto_tree_add_item(nlmsg_tree, hf_ovs_vport_dp_ifindex, tvb, offset,
        4, genl_info->nl_data->encoding);
    offset += 4;

    /* Dissect netlink attributes */
    if (!tvb_reported_length_remaining(tvb, offset))
        return offset;

    {
        struct netlink_ovs_vport_info info;
        info.pinfo = pinfo;
        ovs_dissect_netlink_attributes_to_end(tvb, hf_ovs_vport_attr,
            ett_ovs_vport_attrs, &info, genl_info->nl_data,
            nlmsg_tree, offset, dissect_ovs_vport_attrs);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_netlink_ovs_vport(void)
{
    static hf_register_info hf[] = {
        { &hf_ovs_vport_commands,
            { "Command", "ovs_vport.cmd",
              FT_UINT8, BASE_DEC, VALS(ws_ovs_vport_commands_vals),
              0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_dp_ifindex,
            { "Datapath ifindex", "ovs_vport.dp_ifindex",
              FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_attr,
            { "Attribute type", "ovs_vport.attr_type",
              FT_UINT16, BASE_DEC, VALS(ws_ovs_vport_attr_vals),
              NLA_TYPE_MASK, NULL, HFILL }
        },
        { &hf_ovs_vport_port_no,
            { "Port number", "ovs_vport.port_no",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_type,
            { "Vport type", "ovs_vport.type",
              FT_UINT32, BASE_DEC, VALS(ws_ovs_vport_type_vals),
              0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_name,
            { "Name", "ovs_vport.name",
              FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_upcall_pid,
            { "Upcall PID", "ovs_vport.upcall_pid",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_ifindex,
            { "Interface index", "ovs_vport.ifindex",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_netnsid,
            { "Network namespace ID", "ovs_vport.netnsid",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_rx_packets,
            { "Rx packets", "ovs_vport.stats.rx_packets",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_tx_packets,
            { "Tx packets", "ovs_vport.stats.tx_packets",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_rx_bytes,
            { "Rx bytes", "ovs_vport.stats.rx_bytes",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_tx_bytes,
            { "Tx bytes", "ovs_vport.stats.tx_bytes",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_rx_errors,
            { "Rx errors", "ovs_vport.stats.rx_errors",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_tx_errors,
            { "Tx errors", "ovs_vport.stats.tx_errors",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_rx_dropped,
            { "Rx dropped", "ovs_vport.stats.rx_dropped",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_stats_tx_dropped,
            { "Tx dropped", "ovs_vport.stats.tx_dropped",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_tunnel_attr,
            { "Tunnel attribute type", "ovs_vport.tunnel.attr_type",
              FT_UINT16, BASE_DEC, VALS(ws_ovs_tunnel_attr_vals),
              NLA_TYPE_MASK, NULL, HFILL }
        },
        { &hf_ovs_vport_tunnel_dst_port,
            { "Tunnel destination port",
              "ovs_vport.tunnel.dst_port",
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_vxlan_ext_attr,
            { "VXLAN extension attribute type",
              "ovs_vport.vxlan_ext.attr_type",
              FT_UINT16, BASE_DEC, VALS(ws_ovs_vxlan_ext_vals),
              NLA_TYPE_MASK, NULL, HFILL }
        },
        { &hf_ovs_vport_vxlan_ext_gbp,
            { "VXLAN GBP", "ovs_vport.vxlan_ext.gbp",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_upcall_stats_attr,
            { "Upcall stats attribute type",
              "ovs_vport.upcall_stats.attr_type",
              FT_UINT16, BASE_DEC,
              VALS(ws_ovs_vport_upcall_attr_vals),
              NLA_TYPE_MASK, NULL, HFILL }
        },
        { &hf_ovs_vport_upcall_success,
            { "Upcall success", "ovs_vport.upcall_stats.success",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ovs_vport_upcall_fail,
            { "Upcall fail", "ovs_vport.upcall_stats.fail",
              FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_ovs_vport,
        &ett_ovs_vport_attrs,
        &ett_ovs_vport_stats,
        &ett_ovs_vport_tunnel_attrs,
        &ett_ovs_vport_vxlan_ext_attrs,
        &ett_ovs_vport_upcall_stats_attrs,
    };

    proto_netlink_ovs_vport = proto_register_protocol(
        "Linux ovs_vport (Open vSwitch Vport) protocol",
        "ovs_vport", "ovs_vport");
    proto_register_field_array(proto_netlink_ovs_vport, hf,
        array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    netlink_ovs_vport_handle = register_dissector("ovs_vport",
        dissect_netlink_ovs_vport, proto_netlink_ovs_vport);
}

void
proto_reg_handoff_netlink_ovs_vport(void)
{
    dissector_add_string("genl.family", "ovs_vport",
        netlink_ovs_vport_handle);
}
