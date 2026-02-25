/* netlink-helpers.c
 * Self-contained netlink attribute parsing helpers for out-of-tree plugins.
 *
 * Copyright 2025, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Based on packet-netlink.c and packet-netlink-generic.c from Wireshark.
 * Copyright (c) 2017, Peter Wu <peter@lekensteyn.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "netlink-helpers.h"

#include <epan/exceptions.h>

/* Round up to nearest multiple of 4 */
#ifndef WS_ROUNDUP_4
#define WS_ROUNDUP_4(n) (((n) + 3) & ~3)
#endif

/* Header fields for netlink attribute (NLA) parsing */
static int hf_nla_len;
static int hf_nla_type;
static int hf_nla_type_nested;
static int hf_nla_type_net_byteorder;
static int hf_nla_data;
static int hf_nla_index;
static int hf_nla_padding;

/* Header fields for genl header */
static int hf_genl_version;
static int hf_genl_reserved;

/* Subtrees */
static int ett_nla = -1;
static int ett_nla_type = -1;

void
ovs_netlink_helpers_register(void)
{
    static hf_register_info hf[] = {
        { &hf_nla_len,
            { "Len", "ovs_nla.len",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nla_type,
            { "Type", "ovs_nla.type",
              FT_UINT16, BASE_HEX, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nla_type_nested,
            { "Nested", "ovs_nla.type.nested",
              FT_BOOLEAN, 16, NULL, NLA_F_NESTED,
              NULL, HFILL }
        },
        { &hf_nla_type_net_byteorder,
            { "Network byte order",
              "ovs_nla.type.net_byteorder",
              FT_BOOLEAN, 16, NULL, NLA_F_NET_BYTEORDER,
              NULL, HFILL }
        },
        { &hf_nla_data,
            { "Data", "ovs_nla.data",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nla_index,
            { "Index", "ovs_nla.index",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nla_padding,
            { "Padding", "ovs_nla.padding",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_genl_version,
            { "Family Version", "ovs_genl.version",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_genl_reserved,
            { "Reserved", "ovs_genl.reserved",
              FT_NONE, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_nla,
        &ett_nla_type,
    };

    /* Register under a helper protocol to avoid hf/ett conflicts
     * with Wireshark's built-in netlink dissectors. */
    int proto = proto_register_protocol(
        "OVS Netlink Helpers", "ovs_nla", "ovs_nla");
    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

int
ovs_dissect_genl_header(tvbuff_t *tvb, genl_info_t *genl_info,
    struct packet_netlink_data *nl_data, int hf_cmd)
{
    int offset = 0;

    proto_tree_add_item(genl_info->genl_tree, hf_cmd, tvb, offset, 1,
        ENC_NA);
    offset++;
    proto_tree_add_item(genl_info->genl_tree, hf_genl_version, tvb,
        offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(genl_info->genl_tree, hf_genl_reserved, tvb,
        offset, 2, nl_data->encoding);
    offset += 2;
    return offset;
}

/*
 * Core NLA parser.  Iterates over netlink attributes in a TLV stream,
 * dissecting each header (len, type, flags) and calling the per-family
 * attribute callback to decode the payload.
 *
 * When ett_attrib > 0, the stream is treated as an array of nested
 * attribute groups (used by OVS_METER_ATTR_BANDS).
 */
static int
dissect_attributes_common(tvbuff_t *tvb, int hf_type, int ett_tree,
    int ett_attrib, void *data, struct packet_netlink_data *nl_data,
    proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
    int encoding;
    int padding = (4 - offset) & 3;
    unsigned data_length;
    header_field_info *hfi_type;

    DISSECTOR_ASSERT(nl_data);
    encoding = nl_data->encoding;

    if (length < 0)
        THROW(ReportedBoundsError);

    /* Align to 4 bytes */
    offset += padding;
    if (length < padding)
        THROW(ReportedBoundsError);
    length -= padding;
    data_length = length;

    while (data_length >= 4) {
        unsigned rta_len, rta_type, type;
        proto_item *ti, *type_item;
        proto_tree *attr_tree, *type_tree;

        rta_len = tvb_get_uint16(tvb, offset, encoding);
        if (rta_len < 4)
            break;

        rta_len = MIN(rta_len, data_length);

        attr_tree = proto_tree_add_subtree(tree, tvb, offset, rta_len,
            ett_tree, &ti, "Attribute");

        proto_tree_add_item(attr_tree, hf_nla_len, tvb, offset, 2,
            encoding);
        offset += 2;

        rta_type = tvb_get_uint16(tvb, offset, encoding);
        if (ett_attrib <= 0) {
            /* Regular attribute: dissect type field with NLA flags */
            type = rta_type & NLA_TYPE_MASK;
            type_item = proto_tree_add_item(attr_tree, hf_nla_type,
                tvb, offset, 2, encoding);
            type_tree = proto_item_add_subtree(type_item,
                ett_nla_type);
            proto_tree_add_item(type_tree, hf_nla_type_nested,
                tvb, offset, 2, encoding);
            proto_tree_add_item(type_tree,
                hf_nla_type_net_byteorder,
                tvb, offset, 2, encoding);
            proto_tree_add_uint(type_tree, hf_type, tvb, offset,
                2, type);
            offset += 2;

            if (rta_type & NLA_F_NESTED)
                proto_item_append_text(type_item, ", Nested");

            hfi_type = proto_registrar_get_nth(hf_type);
            if (hfi_type->strings) {
                const char *rta_str;
                if (hfi_type->display & BASE_EXT_STRING) {
                    rta_str = try_val_to_str_ext(type,
                        (value_string_ext *)
                        hfi_type->strings);
                } else {
                    rta_str = try_val_to_str(type,
                        (const value_string *)
                        hfi_type->strings);
                }
                if (rta_str) {
                    proto_item_append_text(type_item,
                        ", %s (%d)", rta_str, type);
                    proto_item_append_text(ti, ": %s",
                        rta_str);
                }
            }

            if (rta_type & NLA_F_NET_BYTEORDER)
                nl_data->encoding = ENC_BIG_ENDIAN;

            if (!cb(tvb, data, nl_data, attr_tree, rta_type,
                offset, rta_len - 4)) {
                proto_tree_add_item(attr_tree, hf_nla_data,
                    tvb, offset, rta_len - 4, ENC_NA);
            }

            if (rta_type & NLA_F_NET_BYTEORDER)
                nl_data->encoding = encoding;
        } else {
            /* Array element: recurse into nested attributes */
            proto_tree_add_item(attr_tree, hf_nla_index, tvb,
                offset, 2, encoding);
            offset += 2;
            proto_item_append_text(ti, " %u", rta_type);

            ovs_dissect_netlink_attributes(tvb, hf_type,
                ett_attrib, data, nl_data, attr_tree, offset,
                rta_len - 4, cb);
        }

        {
            unsigned signalled_len = rta_len;
            rta_len = MIN(WS_ROUNDUP_4(rta_len), data_length);
            if (rta_len > signalled_len) {
                proto_tree_add_item(attr_tree, hf_nla_padding,
                    tvb,
                    offset + signalled_len - 4,
                    rta_len - signalled_len, ENC_NA);
            }
        }

        offset += rta_len - 4;

        if (data_length < rta_len)
            THROW(ReportedBoundsError);
        data_length -= rta_len;
    }

    return offset;
}

int
ovs_dissect_netlink_attributes(tvbuff_t *tvb, int hf_type, int ett,
    void *data, struct packet_netlink_data *nl_data, proto_tree *tree,
    int offset, int length, netlink_attributes_cb_t cb)
{
    return dissect_attributes_common(tvb, hf_type, ett, -1, data, nl_data,
        tree, offset, length, cb);
}

int
ovs_dissect_netlink_attributes_to_end(tvbuff_t *tvb, int hf_type, int ett,
    void *data, struct packet_netlink_data *nl_data, proto_tree *tree,
    int offset, netlink_attributes_cb_t cb)
{
    return dissect_attributes_common(tvb, hf_type, ett, -1, data, nl_data,
        tree, offset,
        tvb_ensure_reported_length_remaining(tvb, offset), cb);
}

int
ovs_dissect_netlink_attributes_array(tvbuff_t *tvb, int hf_type,
    int ett_array, int ett_attrib, void *data,
    struct packet_netlink_data *nl_data, proto_tree *tree,
    int offset, int length, netlink_attributes_cb_t cb)
{
    DISSECTOR_ASSERT(ett_attrib > 0);
    return dissect_attributes_common(tvb, hf_type, ett_array, ett_attrib,
        data, nl_data, tree, offset, length, cb);
}
