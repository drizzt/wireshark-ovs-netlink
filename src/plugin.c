/* plugin.c
 * Plugin registration for Open vSwitch Netlink dissectors
 *
 * Copyright 2025, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL

#include <wireshark.h>
#include <wsutil/plugins.h>
#include <epan/proto.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

/* Netlink helpers registration */
extern void ovs_netlink_helpers_register(void);

/* Dissector registration functions from each OVS family */
extern void proto_register_netlink_ovs_vport(void);
extern void proto_reg_handoff_netlink_ovs_vport(void);

extern void proto_register_netlink_ovs_datapath(void);
extern void proto_reg_handoff_netlink_ovs_datapath(void);

extern void proto_register_netlink_ovs_flow(void);
extern void proto_reg_handoff_netlink_ovs_flow(void);

extern void proto_register_netlink_ovs_packet(void);
extern void proto_reg_handoff_netlink_ovs_packet(void);

extern void proto_register_netlink_ovs_meter(void);
extern void proto_reg_handoff_netlink_ovs_meter(void);

extern void proto_register_netlink_ovs_ct_limit(void);
extern void proto_reg_handoff_netlink_ovs_ct_limit(void);

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

/*
 * Register each OVS family as a separate proto_plugin so Wireshark
 * calls proto_register_* and proto_reg_handoff_* for each dissector.
 * The helpers must be registered first (they provide shared hf/ett).
 */
void
plugin_register(void)
{
    static proto_plugin plug_helpers;
    plug_helpers.register_protoinfo = ovs_netlink_helpers_register;
    plug_helpers.register_handoff = NULL;
    proto_register_plugin(&plug_helpers);

    static proto_plugin plug_vport;
    plug_vport.register_protoinfo = proto_register_netlink_ovs_vport;
    plug_vport.register_handoff = proto_reg_handoff_netlink_ovs_vport;
    proto_register_plugin(&plug_vport);

    static proto_plugin plug_datapath;
    plug_datapath.register_protoinfo = proto_register_netlink_ovs_datapath;
    plug_datapath.register_handoff = proto_reg_handoff_netlink_ovs_datapath;
    proto_register_plugin(&plug_datapath);

    static proto_plugin plug_flow;
    plug_flow.register_protoinfo = proto_register_netlink_ovs_flow;
    plug_flow.register_handoff = proto_reg_handoff_netlink_ovs_flow;
    proto_register_plugin(&plug_flow);

    static proto_plugin plug_packet;
    plug_packet.register_protoinfo = proto_register_netlink_ovs_packet;
    plug_packet.register_handoff = proto_reg_handoff_netlink_ovs_packet;
    proto_register_plugin(&plug_packet);

    static proto_plugin plug_meter;
    plug_meter.register_protoinfo = proto_register_netlink_ovs_meter;
    plug_meter.register_handoff = proto_reg_handoff_netlink_ovs_meter;
    proto_register_plugin(&plug_meter);

    static proto_plugin plug_ct_limit;
    plug_ct_limit.register_protoinfo = proto_register_netlink_ovs_ct_limit;
    plug_ct_limit.register_handoff = proto_reg_handoff_netlink_ovs_ct_limit;
    proto_register_plugin(&plug_ct_limit);
}

uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}
