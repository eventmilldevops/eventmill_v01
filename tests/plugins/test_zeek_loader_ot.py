"""Tests for Zeek OT/ICS protocol log parsers in zeek_loader.py."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def log_dir(tmp_path: Path):
    """Return a temp directory pre-populated with minimal Zeek JSON log files."""
    return tmp_path


def _write_log(log_dir: Path, name: str, entries: list[dict]) -> Path:
    """Write a list of dicts as one-JSON-object-per-line Zeek log."""
    path = log_dir / name
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return path


# ---------------------------------------------------------------------------
# Modbus
# ---------------------------------------------------------------------------

def test_parse_modbus_log_func_code(log_dir):
    """icsnpp-modbus log with numeric function code."""
    _write_log(log_dir, "conn.log", [])  # empty conn so session builds
    _write_log(log_dir, "modbus.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": 3,
            "unit_id": 1,
            "exception": "-",
        },
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49153,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": 16,
            "unit_id": 1,
            "exception": "-",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)

    assert len(session.ot_transactions) == 2

    read_tx = session.ot_transactions[0]
    assert read_tx["protocol"] == "Modbus"
    assert read_tx["function_code"] == 3
    assert read_tx["function_name"] == "Read Holding Registers"
    assert read_tx["is_write"] is False

    write_tx = session.ot_transactions[1]
    assert write_tx["function_code"] == 16
    assert write_tx["function_name"] == "Write Multiple Registers"
    assert write_tx["is_write"] is True


def test_parse_modbus_log_string_func(log_dir):
    """icsnpp-modbus log with string function name."""
    _write_log(log_dir, "modbus.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": "Read Holding Registers",
            "unit_id": 1,
            "exception": "-",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 1
    assert session.ot_transactions[0]["function_name"] == "Read Holding Registers"


def test_parse_modbus_exception(log_dir):
    """Modbus exception responses are flagged."""
    _write_log(log_dir, "modbus.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": 3,
            "unit_id": 1,
            "exception": "ILLEGAL_FUNCTION",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert session.ot_transactions[0]["is_exception"] is True
    assert session.ot_transactions[0]["exception_code"] == "ILLEGAL_FUNCTION"


def test_parse_modbus_detailed_log(log_dir):
    """modbus_detailed.log with register-level detail."""
    _write_log(log_dir, "modbus_detailed.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": 3,
            "register_type": "HOLDING_REGISTER",
            "register_addr": 100,
            "register_value": "0x1234",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 1
    tx = session.ot_transactions[0]
    assert tx["register_type"] == "HOLDING_REGISTER"
    assert tx["register_addr"] == 100


# ---------------------------------------------------------------------------
# DNP3
# ---------------------------------------------------------------------------

def test_parse_dnp3_log(log_dir):
    """icsnpp-dnp3 log with request and reply function codes."""
    _write_log(log_dir, "dnp3.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.2.10",
            "id.orig_p": 49200,
            "id.resp_h": "10.0.2.20",
            "id.resp_p": 20000,
            "fc_request": "READ",
            "fc_reply": "",
        },
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.2.10",
            "id.orig_p": 49201,
            "id.resp_h": "10.0.2.20",
            "id.resp_p": 20000,
            "fc_request": 2,
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 2
    assert session.ot_transactions[0]["protocol"] == "DNP3"
    assert session.ot_transactions[0]["port"] == 20000

    # Second entry has numeric func code → should resolve
    write_tx = session.ot_transactions[1]
    assert write_tx["function_code"] == 2
    assert write_tx["function_name"] == "Write"
    assert write_tx["is_write"] is True


def test_parse_dnp3_control_ops(log_dir):
    """DNP3 control operations flagged correctly."""
    _write_log(log_dir, "dnp3.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.2.10",
            "id.orig_p": 49200,
            "id.resp_h": "10.0.2.20",
            "id.resp_p": 20000,
            "fc_request": 5,  # Direct-Operate
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert session.ot_transactions[0]["is_control"] is True
    assert session.ot_transactions[0]["is_write"] is True


# ---------------------------------------------------------------------------
# BACnet
# ---------------------------------------------------------------------------

def test_parse_bacnet_log(log_dir):
    """icsnpp-bacnet log entries."""
    _write_log(log_dir, "bacnet.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.3.10",
            "id.orig_p": 47808,
            "id.resp_h": "10.0.3.20",
            "id.resp_p": 47808,
            "bvlc_function": "ORIGINAL_UNICAST_NPDU",
            "pdu_type": "CONFIRMED_REQUEST",
            "pdu_service": "readProperty",
            "object_type": "analog-input",
            "property_identifier": "present-value",
        },
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.3.10",
            "id.orig_p": 47808,
            "id.resp_h": "10.0.3.20",
            "id.resp_p": 47808,
            "bvlc_function": "ORIGINAL_UNICAST_NPDU",
            "pdu_type": "CONFIRMED_REQUEST",
            "pdu_service": "writeProperty",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 2
    assert session.ot_transactions[0]["protocol"] == "BACnet"
    assert session.ot_transactions[0]["is_write"] is False
    assert session.ot_transactions[0]["object_type"] == "analog-input"
    assert session.ot_transactions[1]["is_write"] is True


# ---------------------------------------------------------------------------
# S7comm
# ---------------------------------------------------------------------------

def test_parse_s7comm_log(log_dir):
    """icsnpp-s7comm log entries with numeric function codes."""
    _write_log(log_dir, "s7comm.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.4.10",
            "id.orig_p": 49300,
            "id.resp_h": "10.0.4.20",
            "id.resp_p": 102,
            "rosctr": 1,
            "func_code": 4,
        },
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.4.10",
            "id.orig_p": 49301,
            "id.resp_h": "10.0.4.20",
            "id.resp_p": 102,
            "rosctr": 1,
            "func_code": 5,
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 2
    assert session.ot_transactions[0]["protocol"] == "S7comm"
    assert session.ot_transactions[0]["function"] == "Read"
    assert session.ot_transactions[0]["is_write"] is False
    assert session.ot_transactions[1]["function"] == "Write"
    assert session.ot_transactions[1]["is_write"] is True


def test_parse_s7comm_control(log_dir):
    """S7comm PLC-Stop is flagged as control."""
    _write_log(log_dir, "s7comm.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.4.10",
            "id.orig_p": 49300,
            "id.resp_h": "10.0.4.20",
            "id.resp_p": 102,
            "rosctr": 1,
            "func_code": 0x28,  # PLC-Stop
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert session.ot_transactions[0]["is_control"] is True
    assert session.ot_transactions[0]["function"] == "PLC-Stop"


# ---------------------------------------------------------------------------
# EtherNet/IP & CIP
# ---------------------------------------------------------------------------

def test_parse_enip_log(log_dir):
    """icsnpp-enip ENIP encapsulation log."""
    _write_log(log_dir, "enip.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.5.10",
            "id.orig_p": 49400,
            "id.resp_h": "10.0.5.20",
            "id.resp_p": 44818,
            "command": "RegisterSession",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 1
    assert session.ot_transactions[0]["protocol"] == "EtherNet/IP-CIP"
    assert session.ot_transactions[0]["function_name"] == "RegisterSession"


def test_parse_cip_log(log_dir):
    """icsnpp-enip CIP layer log."""
    _write_log(log_dir, "cip.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.5.10",
            "id.orig_p": 49400,
            "id.resp_h": "10.0.5.20",
            "id.resp_p": 44818,
            "service": "Get_Attribute_Single",
            "cip_class_id": "0x01",
            "cip_instance_id": "0x01",
        },
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.5.10",
            "id.orig_p": 49401,
            "id.resp_h": "10.0.5.20",
            "id.resp_p": 44818,
            "service": "Set_Attribute_Single",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 2
    assert session.ot_transactions[0]["is_write"] is False
    assert session.ot_transactions[1]["is_write"] is True  # "set" keyword


# ---------------------------------------------------------------------------
# OPC-UA
# ---------------------------------------------------------------------------

def test_parse_opcua_log(log_dir):
    """icsnpp-opcua-binary log entries."""
    _write_log(log_dir, "opcua_binary.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.6.10",
            "id.orig_p": 49500,
            "id.resp_h": "10.0.6.20",
            "id.resp_p": 4840,
            "msg_type": "MSG",
            "service": "ReadRequest",
        },
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.6.10",
            "id.orig_p": 49501,
            "id.resp_h": "10.0.6.20",
            "id.resp_p": 4840,
            "msg_type": "MSG",
            "service": "WriteRequest",
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 2
    assert session.ot_transactions[0]["protocol"] == "OPC-UA"
    assert session.ot_transactions[0]["is_write"] is False
    assert session.ot_transactions[1]["is_write"] is True


# ---------------------------------------------------------------------------
# conn.log OT fallback (existing behaviour preserved)
# ---------------------------------------------------------------------------

def test_conn_log_ot_service_detection(log_dir):
    """conn.log service field detects OT protocols when no dedicated log exists."""
    _write_log(log_dir, "conn.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "proto": "tcp",
            "service": "modbus",
            "orig_bytes": 100,
            "resp_bytes": 200,
            "orig_pkts": 5,
            "resp_pkts": 5,
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 1
    assert session.ot_transactions[0]["protocol"] == "MODBUS"
    assert session.ot_transactions[0]["src"] == "10.0.1.10"
    assert session.ot_transactions[0]["dst"] == "10.0.1.20"


# ---------------------------------------------------------------------------
# Mixed scenario: standard + OT logs together
# ---------------------------------------------------------------------------

def test_full_mixed_parse(log_dir):
    """Verify standard + OT logs all parsed into one session."""
    _write_log(log_dir, "conn.log", [
        {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "orig_bytes": 500,
            "resp_bytes": 1500,
            "orig_pkts": 10,
            "resp_pkts": 15,
        },
    ])
    _write_log(log_dir, "dns.log", [
        {
            "ts": 1700000000.5,
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.53",
            "query": "example.com",
            "qtype_name": "A",
        },
    ])
    _write_log(log_dir, "modbus.log", [
        {
            "ts": 1700000001.0,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": 3,
            "unit_id": 1,
            "exception": "-",
        },
    ])
    _write_log(log_dir, "dnp3.log", [
        {
            "ts": 1700000002.0,
            "id.orig_h": "10.0.2.10",
            "id.orig_p": 49200,
            "id.resp_h": "10.0.2.20",
            "id.resp_p": 20000,
            "fc_request": 1,
        },
    ])

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)

    # Standard logs parsed
    assert len(session.conversations) == 1
    assert len(session.dns_queries) == 1

    # OT logs parsed
    assert len(session.ot_transactions) == 2
    protocols = {t["protocol"] for t in session.ot_transactions}
    assert "Modbus" in protocols
    assert "DNP3" in protocols


# ---------------------------------------------------------------------------
# Cap at 50k
# ---------------------------------------------------------------------------

def test_ot_transaction_cap(log_dir):
    """OT transactions are capped at 50,000."""
    entries = [
        {
            "ts": 1700000000.0 + i * 0.001,
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.1.20",
            "id.resp_p": 502,
            "func": 3,
            "unit_id": 1,
            "exception": "-",
        }
        for i in range(51000)
    ]
    _write_log(log_dir, "modbus.log", entries)

    from plugins.network_forensics.pcap_metadata_summary.zeek_loader import parse_zeek_logs

    session = parse_zeek_logs(log_dir)
    assert len(session.ot_transactions) == 50000
