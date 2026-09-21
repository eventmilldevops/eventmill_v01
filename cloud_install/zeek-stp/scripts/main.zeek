##! STP/RSTP/MSTP BPDU logging for Zeek
##!
##! Writes stp.log with comprehensive BPDU field extraction including
##! flags decoding (TC, TCA, Proposal, Agreement, Port Role, Learning,
##! Forwarding), bridge/root IDs, path costs, port IDs, timers, and
##! VLAN from System ID Extension.
##!
##! Requires the EventMill::STP packet analyzer plugin to be installed.

module STP;

export {
    ## The STP logging stream identifier
    redef enum Log::ID += { LOG };

    ## Record type for stp.log entries
    type Info: record {
        ## Timestamp of the BPDU
        ts:                time    &log;
        ## Source MAC of the switch sending the BPDU
        src_mac:           string  &log;
        ## Destination MAC (01:80:c2:00:00:00 for STP, 01:00:0c:cc:cc:cd for PVST+)
        dst_mac:           string  &log;
        ## Protocol version: 0=STP, 2=RSTP, 3=MSTP
        version:           count   &log &optional;
        ## BPDU type: "Config", "RSTP", or "TCN"
        bpdu_type:         string  &log;
        ## Raw flags byte value
        flags:             count   &log &optional;
        ## Topology Change flag (bit 0)
        tc:                bool    &log &default=F;
        ## Topology Change Acknowledgment flag (bit 7)
        tca:               bool    &log &default=F;
        ## RSTP Proposal flag (bit 1)
        proposal:          bool    &log &default=F;
        ## RSTP Agreement flag (bit 6)
        agreement:         bool    &log &default=F;
        ## RSTP Port Role: Unknown, Alternate/Backup, Root, Designated
        port_role:         string  &log &default="Unknown";
        ## RSTP Learning state (bit 4)
        learning:          bool    &log &default=F;
        ## RSTP Forwarding state (bit 5)
        forwarding:        bool    &log &default=F;
        ## Root Bridge Priority (full 16-bit including sys-id-ext)
        root_priority:     count   &log &optional;
        ## Root Bridge MAC address
        root_mac:          string  &log &optional;
        ## VLAN ID from Root Bridge System ID Extension (lower 12 bits)
        root_sys_id_ext:   count   &log &optional;
        ## Root Path Cost from this bridge to root
        root_path_cost:    count   &log &optional;
        ## Sending Bridge Priority (full 16-bit including sys-id-ext)
        bridge_priority:   count   &log &optional;
        ## Sending Bridge MAC address
        bridge_mac:        string  &log &optional;
        ## VLAN ID from Bridge System ID Extension (lower 12 bits)
        bridge_sys_id_ext: count   &log &optional;
        ## Port Identifier
        port_id:           count   &log &optional;
        ## Message Age in seconds
        message_age:       count   &log &optional;
        ## Max Age in seconds
        max_age:           count   &log &optional;
        ## Hello Time in seconds
        hello_time:        count   &log &optional;
        ## Forward Delay in seconds
        forward_delay:     count   &log &optional;
    };
}

# Register our STP analyzer as the LLC handler for the Ethernet packet analyzer.
# STP BPDUs arrive via 802.3 frames: LLC DSAP=0x42 (standard) or SNAP/PVST+.
redef PacketAnalyzer::ETHERNET::llc_analyzer = PacketAnalyzer::ANALYZER_STP;

event zeek_init() &priority=5 {
    Log::create_stream(STP::LOG, [$columns=Info, $path="stp"]);
}

## Handler for Config BPDUs (type 0x00) and RSTP BPDUs (type 0x02).
## Decodes the flags byte into individual fields and logs to stp.log.
event stp_config_bpdu(src_mac: string, dst_mac: string, version: count,
                       bpdu_type_val: count, flags: count,
                       root_priority: count, root_mac: string,
                       root_path_cost: count, bridge_priority: count,
                       bridge_mac: string, port_id: count,
                       message_age: count, max_age: count,
                       hello_time: count, forward_delay: count) {
    local info: Info;
    info$ts = network_time();
    info$src_mac = src_mac;
    info$dst_mac = dst_mac;
    info$version = version;

    # BPDU type name
    if ( bpdu_type_val == 0 )
        info$bpdu_type = "Config";
    else if ( bpdu_type_val == 2 )
        info$bpdu_type = "RSTP";
    else
        info$bpdu_type = fmt("0x%02x", bpdu_type_val);

    info$flags = flags;

    # Decode RSTP flags byte
    info$tc         = (flags & 0x01) != 0;   # Bit 0: Topology Change
    info$proposal   = (flags & 0x02) != 0;   # Bit 1: Proposal
    info$learning   = (flags & 0x10) != 0;   # Bit 4: Learning
    info$forwarding = (flags & 0x20) != 0;   # Bit 5: Forwarding
    info$agreement  = (flags & 0x40) != 0;   # Bit 6: Agreement
    info$tca        = (flags & 0x80) != 0;   # Bit 7: TC Acknowledgment

    # Bits 2-3: Port Role
    local role_bits = (flags / 4) % 4;  # (flags >> 2) & 0x03
    if ( role_bits == 0 )
        info$port_role = "Unknown";
    else if ( role_bits == 1 )
        info$port_role = "Alternate/Backup";
    else if ( role_bits == 2 )
        info$port_role = "Root";
    else if ( role_bits == 3 )
        info$port_role = "Designated";

    info$root_priority  = root_priority;
    info$root_mac       = root_mac;
    info$root_sys_id_ext = root_priority % 4096;   # Lower 12 bits = VLAN
    info$root_path_cost = root_path_cost;
    info$bridge_priority  = bridge_priority;
    info$bridge_mac       = bridge_mac;
    info$bridge_sys_id_ext = bridge_priority % 4096;  # Lower 12 bits = VLAN
    info$port_id      = port_id;
    info$message_age  = message_age;
    info$max_age      = max_age;
    info$hello_time   = hello_time;
    info$forward_delay = forward_delay;

    Log::write(STP::LOG, info);
}

## Handler for Topology Change Notification BPDUs (type 0x80).
## TCN BPDUs have no payload — just the fact that a topology change was detected.
event stp_tcn_bpdu(src_mac: string, dst_mac: string) {
    local info: Info;
    info$ts = network_time();
    info$src_mac = src_mac;
    info$dst_mac = dst_mac;
    info$bpdu_type = "TCN";
    info$tc = T;

    Log::write(STP::LOG, info);
}
