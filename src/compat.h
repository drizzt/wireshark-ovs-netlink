/* compat.h
 * Wireshark version compatibility macros.
 *
 * Provides shims so the plugin builds against Wireshark 4.2+
 * through the current release without ifdefs in the main sources.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __OVS_COMPAT_H__
#define __OVS_COMPAT_H__

#include <wireshark.h>

/*
 * Wireshark 4.4 split wsutil/array.h out of the main headers and
 * added the plugin_describe() entry point (wsutil/plugins.h).
 */
#if WIRESHARK_VERSION_MAJOR > 4 || \
    (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 4)
#include <wsutil/array.h>
#include <wsutil/plugins.h>
#define OVS_HAVE_PLUGIN_DESCRIBE
#endif

/*
 * Wireshark 4.4 renamed tvb accessors from GLib to C99 integer types.
 * Map the new names back to the old ones for Wireshark < 4.4.
 */
#if WIRESHARK_VERSION_MAJOR < 4 || \
    (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR < 4)
#define tvb_get_uint16  tvb_get_guint16
#define tvb_get_int32   tvb_get_gint32
#endif

/*
 * Wireshark 4.6 renamed val_to_str_wmem() to val_to_str().
 * Provide a single wrapper name for both.
 */
#if WIRESHARK_VERSION_MAJOR > 4 || \
    (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 6)
#define ovs_val_to_str val_to_str
#else
#define ovs_val_to_str val_to_str_wmem
#endif

#endif /* __OVS_COMPAT_H__ */
