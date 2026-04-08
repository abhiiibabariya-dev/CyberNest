"""
CyberNest Parser Unit Tests.

Tests all major parsers with realistic sample data to verify correct ECS mapping.
"""

from __future__ import annotations

import json
import sys
import os

import pytest

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from parser.parsers.windows_evtx import parse_windows_evtx
from parser.parsers.syslog_parser import parse_syslog_rfc3164, parse_syslog_rfc5424, parse_syslog
from parser.parsers.cef_parser import parse_cef
from parser.parsers.suricata_eve import parse_suricata_eve
from parser.parsers.nginx_apache import parse_nginx_apache


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

WINDOWS_EVENT_4625_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2024-03-15T10:23:45.1234567Z"/>
    <EventRecordID>123456</EventRecordID>
    <Correlation/>
    <Execution ProcessID="636" ThreadID="1234"/>
    <Channel>Security</Channel>
    <Computer>DC01.corp.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">admin_test</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="WorkstationName">ATTACKER-PC</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x0</Data>
    <Data Name="ProcessName">-</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="IpPort">49832</Data>
  </EventData>
</Event>"""

WINDOWS_EVENT_4688_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2024-03-15T14:30:12.9876543Z"/>
    <EventRecordID>234567</EventRecordID>
    <Correlation/>
    <Execution ProcessID="4" ThreadID="148"/>
    <Channel>Security</Channel>
    <Computer>WKS01.corp.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1234567890-987654321-111111111-1001</Data>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="NewProcessId">0x1a2b</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x0f0f</Data>
    <Data Name="CommandLine">cmd.exe /c whoami /all</Data>
    <Data Name="TargetUserSid">S-1-5-21-1234567890-987654321-111111111-1001</Data>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0x5abcd</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-8192</Data>
  </EventData>
</Event>"""

SYSLOG_RFC3164_SAMPLE = '<134>Mar 15 10:23:45 webserver01 sshd[12345]: Failed password for root from 10.0.0.55 port 22222 ssh2'

SYSLOG_RFC5424_SAMPLE = '<165>1 2024-03-15T10:23:45.123456+00:00 fw01.corp.local snort 12345 IDS-ALERT [sigSrc@12345 srcIp="10.0.0.55" dstIp="172.16.0.10" signature="ET SCAN Nmap"] Nmap scan detected from 10.0.0.55'

CEF_SAMPLE = 'CEF:0|Security|ThreatDefense|1.0|100|Malware detected|9|src=10.0.0.55 spt=1234 dst=172.16.0.10 dpt=443 duser=admin act=blocked fname=malware.exe fileHash=a1b2c3d4e5f6 msg=Trojan.GenericKD detected rt=1710499425000'

SURICATA_EVE_ALERT = json.dumps({
    "timestamp": "2024-03-15T10:23:45.123456+0000",
    "flow_id": 1234567890,
    "in_iface": "eth0",
    "event_type": "alert",
    "src_ip": "10.0.0.55",
    "src_port": 45678,
    "dest_ip": "172.16.0.10",
    "dest_port": 80,
    "proto": "TCP",
    "community_id": "1:abc123",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2024001,
        "rev": 3,
        "signature": "ET MALWARE Win32/Emotet CnC Beacon",
        "category": "A Network Trojan was detected",
        "severity": 1,
        "metadata": {
            "mitre_technique_id": ["T1071.001"],
            "mitre_tactic_id": ["TA0011"],
        },
    },
    "payload": "R0VUIC8gSFRUUC8xLjE=",
    "payload_printable": "GET / HTTP/1.1",
})

NGINX_ACCESS_LOG = '192.168.1.100 - frank [15/Mar/2024:10:23:45 +0000] "GET /api/users?page=1 HTTP/1.1" 200 4523 "https://app.example.com/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWindowsEvtxParser:

    def test_windows_event_4625(self) -> None:
        """Test parsing of Windows Event 4625 (Failed Logon)."""
        result = parse_windows_evtx(WINDOWS_EVENT_4625_XML)

        assert result is not None
        assert result["event"]["code"] == "4625"
        assert result["event"]["action"] == "logon-failed"
        assert result["event"]["outcome"] == "failure"
        assert result["event"]["category"] == ["authentication"]
        assert result["event"]["module"] == "windows"

        # User fields
        assert result["user"]["name"] == "admin_test"
        assert result["user"]["domain"] == "CORP"

        # Source IP
        assert result["source"]["ip"] == "192.168.1.100"
        assert result["source"]["port"] == 49832

        # Host
        assert result["host"]["name"] == "DC01.corp.local"

        # Failure reason
        assert "Incorrect password" in result["event"]["reason"]

        # Winlog-specific
        assert result["winlog"]["logon_type"] == "3"
        assert result["winlog"]["authentication_package"] == "NTLM"
        assert result["winlog"]["workstation_name"] == "ATTACKER-PC"
        assert result["winlog"]["event_id"] == "4625"

        # Timestamp
        assert "2024-03-15T10:23:45" in result["@timestamp"]

        # Related
        assert "192.168.1.100" in result["related"]["ip"]
        assert "admin_test" in result["related"]["user"]

        # CyberNest metadata
        assert result["cybernest"]["parser_name"] == "windows_evtx"
        assert result["cybernest"]["parse_status"] == "success"

    def test_windows_event_4688(self) -> None:
        """Test parsing of Windows Event 4688 (Process Creation)."""
        result = parse_windows_evtx(WINDOWS_EVENT_4688_XML)

        assert result is not None
        assert result["event"]["code"] == "4688"
        assert result["event"]["action"] == "process-created"
        assert result["event"]["outcome"] == "success"
        assert result["event"]["category"] == ["process"]
        assert result["event"]["type"] == ["start"]

        # Process fields
        assert result["process"]["name"] == "cmd.exe"
        assert result["process"]["executable"] == "C:\\Windows\\System32\\cmd.exe"
        assert result["process"]["command_line"] == "cmd.exe /c whoami /all"
        assert result["process"]["parent"]["name"] == "explorer.exe"
        assert result["process"]["parent"]["executable"] == "C:\\Windows\\explorer.exe"

        # User
        assert result["user"]["name"] == "jsmith"
        assert result["user"]["domain"] == "CORP"

        # Host
        assert result["host"]["name"] == "WKS01.corp.local"

        # Timestamp
        assert "2024-03-15T14:30:12" in result["@timestamp"]

        # Message
        assert "cmd.exe" in result["message"]


class TestSyslogParser:

    def test_syslog_rfc3164(self) -> None:
        """Test parsing of RFC 3164 syslog message."""
        result = parse_syslog_rfc3164(SYSLOG_RFC3164_SAMPLE)

        assert result is not None
        assert result["event"]["dataset"] == "syslog.rfc3164"

        # Host
        assert result["host"]["name"] == "webserver01"
        assert result["host"]["hostname"] == "webserver01"

        # Process
        assert result["process"]["name"] == "sshd"
        assert result["process"]["pid"] == 12345

        # Message
        assert "Failed password for root" in result["message"]

        # Log metadata
        assert result["log"]["level"] == "informational"
        assert result["log"]["syslog"]["facility"]["code"] == 16  # local0
        assert result["log"]["syslog"]["severity"]["code"] == 6   # informational

        # Related
        assert "webserver01" in result["related"]["hosts"]

    def test_syslog_rfc5424(self) -> None:
        """Test parsing of RFC 5424 syslog message."""
        result = parse_syslog_rfc5424(SYSLOG_RFC5424_SAMPLE)

        assert result is not None
        assert result["event"]["dataset"] == "syslog.rfc5424"

        # Host
        assert result["host"]["name"] == "fw01.corp.local"

        # Process
        assert result["process"]["name"] == "snort"
        assert result["process"]["pid"] == 12345

        # Structured data
        assert result["log"]["syslog"]["version"] == "1"
        assert result["log"]["syslog"]["msgid"] == "IDS-ALERT"
        sd = result["log"]["syslog"]["structured_data"]
        assert sd is not None
        assert "sigSrc@12345" in sd
        assert sd["sigSrc@12345"]["srcIp"] == "10.0.0.55"

        # Message
        assert "Nmap scan detected" in result["message"]

    def test_syslog_auto_detect(self) -> None:
        """Test syslog auto-detection between RFC3164 and RFC5424."""
        # RFC 3164
        result3164 = parse_syslog(SYSLOG_RFC3164_SAMPLE)
        assert result3164["event"]["dataset"] == "syslog.rfc3164"

        # RFC 5424
        result5424 = parse_syslog(SYSLOG_RFC5424_SAMPLE)
        assert result5424["event"]["dataset"] == "syslog.rfc5424"


class TestCEFParser:

    def test_cef_parser(self) -> None:
        """Test parsing of CEF message with extensions."""
        result = parse_cef(CEF_SAMPLE)

        assert result is not None

        # CEF header
        assert result["cef"]["version"] == "0"
        assert result["cef"]["device_vendor"] == "Security"
        assert result["cef"]["device_product"] == "ThreatDefense"
        assert result["cef"]["signature_id"] == "100"
        assert result["cef"]["name"] == "Malware detected"
        assert result["cef"]["severity"] == "9"

        # Event
        assert result["event"]["code"] == "100"
        assert result["event"]["severity"] >= 90  # severity 9 -> critical
        assert result["event"]["action"] == "blocked"  # from act= extension

        # Source/Destination
        assert result["source"]["ip"] == "10.0.0.55"
        assert result["source"]["port"] == 1234
        assert result["destination"]["ip"] == "172.16.0.10"
        assert result["destination"]["port"] == 443

        # User
        assert result["user"]["name"] == "admin"

        # File
        assert result["file"]["name"] == "malware.exe"

        # Observer
        assert result["observer"]["vendor"] == "Security"
        assert result["observer"]["product"] == "ThreatDefense"

        # Related IPs
        assert "10.0.0.55" in result["related"]["ip"]
        assert "172.16.0.10" in result["related"]["ip"]

        # Timestamp from rt= (epoch millis)
        assert "2024-03-15" in result["@timestamp"]

        # CyberNest metadata
        assert result["cybernest"]["parser_name"] == "cef"


class TestSuricataEVEParser:

    def test_suricata_eve(self) -> None:
        """Test parsing of Suricata EVE alert JSON."""
        result = parse_suricata_eve(SURICATA_EVE_ALERT)

        assert result is not None

        # Event
        assert result["event"]["kind"] == "alert"
        assert "intrusion_detection" in result["event"]["category"]
        assert result["event"]["action"] == "allowed"

        # Rule
        assert result["rule"]["id"] == "2024001"
        assert "Emotet" in result["rule"]["name"]
        assert result["rule"]["category"] == "A Network Trojan was detected"

        # Source/Destination
        assert result["source"]["ip"] == "10.0.0.55"
        assert result["source"]["port"] == 45678
        assert result["destination"]["ip"] == "172.16.0.10"
        assert result["destination"]["port"] == 80

        # Network
        assert result["network"]["transport"] == "tcp"
        assert result["network"]["community_id"] == "1:abc123"

        # MITRE ATT&CK
        assert result["threat"]["framework"] == "MITRE ATT&CK"
        assert result["threat"]["technique"][0]["id"] == "T1071.001"

        # Timestamp
        assert "2024-03-15" in result["@timestamp"]

        # Related
        assert "10.0.0.55" in result["related"]["ip"]
        assert "172.16.0.10" in result["related"]["ip"]

        # CyberNest metadata
        assert result["cybernest"]["parser_name"] == "suricata_eve"


class TestNginxApacheParser:

    def test_nginx_access(self) -> None:
        """Test parsing of Nginx/Apache combined access log."""
        result = parse_nginx_apache(NGINX_ACCESS_LOG)

        assert result is not None

        # Event
        assert result["event"]["category"] == ["web"]
        assert result["event"]["action"] == "access"
        assert result["event"]["outcome"] == "success"

        # Source IP
        assert result["source"]["ip"] == "192.168.1.100"

        # HTTP
        assert result["http"]["request"]["method"] == "GET"
        assert result["http"]["response"]["status_code"] == 200
        assert result["http"]["response"]["bytes"] == 4523
        assert result["http"]["request"]["referrer"] == "https://app.example.com/dashboard"
        assert result["http"]["version"] == "1.1"

        # URL
        assert result["url"]["original"] == "/api/users?page=1"
        assert result["url"]["path"] == "/api/users"
        assert result["url"]["query"] == "page=1"

        # User agent
        assert "Mozilla/5.0" in result["user_agent"]["original"]

        # User (auth)
        assert result["user"]["name"] == "frank"

        # Timestamp
        assert "2024-03-15" in result["@timestamp"]

        # Related
        assert "192.168.1.100" in result["related"]["ip"]

        # CyberNest metadata
        assert result["cybernest"]["parser_name"] == "nginx_apache"


class TestParserRegistry:

    def test_registered_parsers(self) -> None:
        """Test that all parsers are registered."""
        from parser.parsers import list_parsers
        parsers = list_parsers()
        expected = [
            "windows_evtx", "syslog_rfc3164", "syslog_rfc5424", "syslog",
            "cef", "leef", "json", "nginx_apache", "suricata_eve", "zeek",
            "auditd", "aws_cloudtrail", "palo_alto", "fortinet", "cisco_asa",
        ]
        for name in expected:
            assert name in parsers, f"Parser '{name}' not registered"

    def test_detect_windows(self) -> None:
        """Test auto-detection of Windows Event XML."""
        from parser.parsers import detect_parser
        assert detect_parser(WINDOWS_EVENT_4625_XML) == "windows_evtx"

    def test_detect_cef(self) -> None:
        """Test auto-detection of CEF format."""
        from parser.parsers import detect_parser
        assert detect_parser(CEF_SAMPLE) == "cef"

    def test_detect_syslog(self) -> None:
        """Test auto-detection of syslog format."""
        from parser.parsers import detect_parser
        assert detect_parser(SYSLOG_RFC3164_SAMPLE) == "syslog"

    def test_detect_suricata(self) -> None:
        """Test auto-detection of Suricata EVE JSON."""
        from parser.parsers import detect_parser
        data = json.loads(SURICATA_EVE_ALERT)
        assert detect_parser(data) == "suricata_eve"

    def test_detect_nginx(self) -> None:
        """Test auto-detection of Nginx access log."""
        from parser.parsers import detect_parser
        assert detect_parser(NGINX_ACCESS_LOG) == "nginx_apache"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
