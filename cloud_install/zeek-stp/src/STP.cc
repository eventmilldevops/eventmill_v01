/**
 * STP/RSTP/MSTP BPDU Packet Analyzer for Zeek
 *
 * Registered as the LLC analyzer in the Ethernet packet analysis chain.
 * When Zeek encounters an 802.3 frame (EtherType <= 1500), the Ethernet
 * analyzer dispatches the LLC payload to us. We check for standard STP
 * (DSAP=0x42 / SSAP=0x42) or Cisco PVST+ (SNAP: OUI=00:00:0c, PID=0x010b)
 * and parse the BPDU.
 *
 * BPDU format (after 3-byte LLC header):
 *   Offset  Size  Field
 *   0       2     Protocol ID (always 0x0000 for STP)
 *   2       1     Version (0=STP, 2=RSTP, 3=MSTP)
 *   3       1     BPDU Type (0x00=Config, 0x02=RSTP, 0x80=TCN)
 *   4       1     Flags (TC, Proposal, PortRole, Learning, Forwarding, Agreement, TCA)
 *   5-6     2     Root Bridge Priority (includes System ID Extension / VLAN)
 *   7-12    6     Root Bridge MAC
 *   13-16   4     Root Path Cost
 *   17-18   2     Bridge Priority (includes System ID Extension / VLAN)
 *   19-24   6     Bridge MAC
 *   25-26   2     Port Identifier
 *   27-28   2     Message Age (1/256 seconds)
 *   29-30   2     Max Age (1/256 seconds)
 *   31-32   2     Hello Time (1/256 seconds)
 *   33-34   2     Forward Delay (1/256 seconds)
 */

#include "STP.h"

#include <cstdio>
#include <string>

#include <zeek/Event.h>
#include <zeek/Val.h>
#include <zeek/ZeekString.h>

#include "events.bif.h"

using namespace zeek::packet_analysis::EventMill::STP;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// STPAnalyzer
// ---------------------------------------------------------------------------

STPAnalyzer::STPAnalyzer() : zeek::packet_analysis::Analyzer("STP") {}

bool STPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    // data points to the start of the LLC payload (first byte = DSAP).
    // LLC header: DSAP(1) + SSAP(1) + Control(1) = 3 bytes minimum.
    if (len < 3)
        return false;

    uint8_t dsap = data[0];
    uint8_t ssap = data[1];

    const uint8_t* bpdu;
    size_t bpdu_len;

    if (dsap == 0x42 && ssap == 0x42) {
        // Standard 802.1D LLC: DSAP=0x42, SSAP=0x42
        bpdu = data + 3;
        bpdu_len = len - 3;
    } else if (dsap == 0xAA && ssap == 0xAA && len >= 8
               && data[2] == 0x03           // LLC Control
               && data[3] == 0x00 && data[4] == 0x00 && data[5] == 0x0C  // OUI = Cisco
               && data[6] == 0x01 && data[7] == 0x0B) {  // PID = PVST+
        // Cisco PVST+ — SNAP encapsulation
        bpdu = data + 8;
        bpdu_len = len - 8;
    } else {
        return true;  // Not STP — silently pass (other LLC protocols)
    }

    // Need at least: Protocol ID(2) + Version(1) + Type(1) = 4 bytes
    if (bpdu_len < 4)
        return false;

    // Verify STP Protocol Identifier = 0x0000
    if (bpdu[0] != 0x00 || bpdu[1] != 0x00)
        return true;  // Not STP

    uint8_t version = bpdu[2];
    uint8_t bpdu_type = bpdu[3];

    // Extract source and destination MACs (set by Ethernet analyzer)
    std::string src_mac_str = packet->l2_src ? mac_to_string(packet->l2_src) : "";
    std::string dst_mac_str = packet->l2_dst ? mac_to_string(packet->l2_dst) : "";

    // --- TCN BPDU (type 0x80) — no payload beyond the type field ---
    if (bpdu_type == 0x80) {
        if (stp_tcn_bpdu) {
            event_mgr.Enqueue(stp_tcn_bpdu,
                zeek::make_intrusive<zeek::StringVal>(src_mac_str),
                zeek::make_intrusive<zeek::StringVal>(dst_mac_str));
        }
        return true;
    }

    // --- Config BPDU (0x00) or RSTP BPDU (0x02) — 35 bytes minimum ---
    if (bpdu_len < 35)
        return false;

    uint8_t flags = bpdu[4];

    // Root Bridge ID: priority (2 bytes, big-endian) + MAC (6 bytes)
    uint16_t root_prio = (static_cast<uint16_t>(bpdu[5]) << 8) | bpdu[6];
    std::string root_mac_str = mac_to_string(bpdu + 7);

    // Root Path Cost: 4 bytes big-endian
    uint32_t root_path_cost = (static_cast<uint32_t>(bpdu[13]) << 24) |
                               (static_cast<uint32_t>(bpdu[14]) << 16) |
                               (static_cast<uint32_t>(bpdu[15]) << 8)  |
                               bpdu[16];

    // Bridge ID: priority (2 bytes) + MAC (6 bytes)
    uint16_t bridge_prio = (static_cast<uint16_t>(bpdu[17]) << 8) | bpdu[18];
    std::string bridge_mac_str = mac_to_string(bpdu + 19);

    // Port Identifier: 2 bytes
    uint16_t port_id = (static_cast<uint16_t>(bpdu[25]) << 8) | bpdu[26];

    // Timers: 2 bytes each, in 1/256 second units — convert to whole seconds
    uint16_t msg_age_raw  = (static_cast<uint16_t>(bpdu[27]) << 8) | bpdu[28];
    uint16_t max_age_raw  = (static_cast<uint16_t>(bpdu[29]) << 8) | bpdu[30];
    uint16_t hello_raw    = (static_cast<uint16_t>(bpdu[31]) << 8) | bpdu[32];
    uint16_t fwd_raw      = (static_cast<uint16_t>(bpdu[33]) << 8) | bpdu[34];

    if (stp_config_bpdu) {
        event_mgr.Enqueue(stp_config_bpdu,
            zeek::make_intrusive<zeek::StringVal>(src_mac_str),
            zeek::make_intrusive<zeek::StringVal>(dst_mac_str),
            zeek::val_mgr->Count(version),
            zeek::val_mgr->Count(bpdu_type),
            zeek::val_mgr->Count(flags),
            zeek::val_mgr->Count(root_prio),
            zeek::make_intrusive<zeek::StringVal>(root_mac_str),
            zeek::val_mgr->Count(root_path_cost),
            zeek::val_mgr->Count(bridge_prio),
            zeek::make_intrusive<zeek::StringVal>(bridge_mac_str),
            zeek::val_mgr->Count(port_id),
            zeek::val_mgr->Count(msg_age_raw / 256),
            zeek::val_mgr->Count(max_age_raw / 256),
            zeek::val_mgr->Count(hello_raw / 256),
            zeek::val_mgr->Count(fwd_raw / 256));
    }

    return true;
}
