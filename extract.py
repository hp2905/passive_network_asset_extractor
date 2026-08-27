#!/usr/bin/env python3
"""
extract.py - passive asset identification from a network capture.

Reads a PCAP and produces an asset inventory WITHOUT sending a single packet.
Every attribute carries accumulated evidence with provenance and a confidence
tier. Contradictions are preserved rather than overwritten, since disagreement
between sources is itself informative.

    python extract.py hospital.pcap
    python extract.py hospital.pcap --score ground_truth.csv

Outputs
    assets.csv    one row per device, best-confidence value per attribute
    evidence.csv  every observation with source, tier and observation count

EVIDENCE TIERS (higher wins when values conflict)
    T1 0.95  SELF-DECLARED   device states it: BACnet I-Am, IPP make-and-model,
                             RTSP Server banner, DHCP hostname, LDAP bind DN
    T2 0.75  SEMI-EXPLICIT   OUI vendor, DHCP option-55, HTTP Server header,
                             raw stack signature
    T3 0.50  INFERRED        TCP stack signature -> OS, service direction -> role
    T4 0.30  WEAK            IP-header-only OS, timing regularity, VLAN zone

KNOWN LIMITS
  * The signature tables (STACK_SIGS, IP_SIGS) cover a limited set of stacks.
    A host whose signature is not listed receives a family-level label instead
    of an exact one. The raw signature is recorded in every case, so an
    unmatched host remains a resolvable lead rather than a dead end.
  * Presence is detectable from a single frame, but identity requires the
    device to transmit something carrying an IP header. Hosts observed only
    via ARP yield vendor and VLAN, never an operating system. This is a
    property of passive analysis rather than a defect.
  * Identity is keyed on MAC address. Hosts behind NAT collapse into a single
    entry, and routers appear to own every IP address behind them.
"""

import argparse
import binascii
import os
import csv
import re
import statistics
import subprocess
import sys
from collections import defaultdict

T1, T2, T3, T4 = 0.95, 0.75, 0.50, 0.30
TIER_NAME = {T1: "self-declared", T2: "semi-explicit", T3: "inferred", T4: "weak"}

# ---------------------------------------------------------------------------
# TCP stack signatures: (initial_ttl, window, wscale, has_ts, has_sack)
# wscale None = option absent. Includes a small set of OT and embedded stacks,
# which fingerprinters aimed at IT networks typically omit.
# ---------------------------------------------------------------------------
STACK_SIGS = {
    (128, 64240, 8, False, True): ("Windows 10/11", "workstation"),
    (128, 65535, 8, False, True): ("Windows Server", "server"),
    (64, 29200, 7, True, True): ("Linux (modern kernel)", "server"),
    (64, 5840, 2, True, True): ("Embedded Linux", "appliance"),
    (64, 8192, None, False, True): ("Embedded RTOS", "embedded device"),
    (255, 4096, None, False, False): ("VxWorks / industrial stack", "plc"),
    (64, 16384, 0, False, True): ("Printer firmware", "printer"),
    # Additional general-purpose stacks common on hospital IT segments.
    (128, 8192, 0, False, True): ("Windows XP / Server 2003", "workstation"),
    (128, 16384, 0, False, True): ("Windows XP / Server 2003", "workstation"),
    (64, 65535, 6, True, True): ("FreeBSD / macOS family", "workstation"),
    (64, 65535, 5, True, True): ("macOS / iOS family", "workstation"),
    (64, 14600, 7, True, True): ("Linux (older kernel)", "server"),
    (64, 5720, 7, True, True): ("Linux (older kernel)", "server"),
    (64, 65535, 7, True, True): ("Linux (tuned)", "server"),
    (64, 4380, 4, True, True): ("Android / embedded Linux", "mobile device"),
    # Constrained embedded stacks seen on medical and building equipment.
    (64, 2048, None, False, False): ("minimal embedded stack", "embedded device"),
    (64, 1460, None, False, False): ("minimal embedded stack", "embedded device"),
    (255, 8192, None, False, True): ("industrial stack", "plc"),
    (255, 16384, None, False, True): ("industrial stack", "plc"),
    (128, 65535, 0, False, True): ("Windows (no scaling)", "workstation"),
}

# ---------------------------------------------------------------------------
# IP-header-only signatures: (initial_ttl, df_set, ip_id_mode)
#
# Three features rather than six, so these are filed at T4 and a TCP signature
# always outranks them. Their value lies in covering UDP-only equipment such as
# BACnet controllers, SNMP agents and syslog senders, which TCP fingerprinting
# cannot reach at all.
#
# TTL 255 is deliberately absent from this table. It is the default for
# industrial stacks and for Solaris and AIX alike, so it maps to an explicitly
# ambiguous label that refine_ambiguous() narrows only where independent
# evidence supports a verdict.
# ---------------------------------------------------------------------------
IP_SIGS = {
    (64, True, "zero"): "Linux (modern kernel)",
    (64, True, "incrementing"): "embedded Linux / RTOS",
    (64, False, "incrementing"): "embedded / minimal stack",
    (128, True, "incrementing"): "Windows family",
    (128, True, "random"): "Windows family",
}

# Row caps for passes that read payloads or repeated announcements. Identity
# strings do not vary between messages from the same host, so a sample is as
# informative as the full set at a fraction of the cost. Raised with
# --sample-limit when a capture is expected to contain rare late-appearing
# values.
# Ports at or above this value are treated as ephemeral. Connections to them
# are not evidence of an offered service.
EPHEMERAL_PORT_FLOOR = 32768

PAYLOAD_SAMPLE_LIMIT = 3000
ANNOUNCEMENT_SAMPLE_LIMIT = 2000

AMBIGUOUS_TTL255 = "TTL-255 stack (industrial OR Solaris/AIX)"

# Well-known service ports -> (service, role when SERVING, role when CONSUMING)
PORT_ROLES = {
    502: ("modbus", "plc / modbus outstation", "scada master"),
    20000: ("dnp3", "dnp3 outstation", "dnp3 master"),
    2575: ("hl7-mllp", "hl7 receiver", "hl7 sender"),
    11112: ("dicom", "pacs / image archive", "imaging modality"),
    104: ("dicom", "pacs / image archive", "imaging modality"),
    1883: ("mqtt", "mqtt broker", "iot gateway"),
    389: ("ldap", "directory server", "domain member"),
    636: ("ldaps", "directory server", "domain member"),
    445: ("smb", "file / domain server", "domain member"),
    88: ("kerberos", "kdc / domain controller", "domain member"),
    631: ("ipp", "printer", "print client"),
    9100: ("jetdirect", "printer", "print client"),
    554: ("rtsp", "camera / video source", "video management server"),
    80: ("http", "web server", "web client"),
    443: ("https", "web server", "web client"),
    53: ("dns", "dns server", "dns client"),
    47808: ("bacnet", "bacnet device", "bacnet device"),
    123: ("ntp", "time server", "time client"),
    161: ("snmp", "snmp agent", "snmp manager"),
    514: ("syslog", "syslog collector", "syslog sender"),
    22: ("ssh", "ssh server", "ssh client"),
    23: ("telnet", "telnet server", "telnet client"),
    21: ("ftp", "ftp server", "ftp client"),
    25: ("smtp", "mail server", "mail client"),
    3389: ("rdp", "rdp host", "rdp client"),
    5900: ("vnc", "vnc host", "vnc client"),
    1900: ("ssdp", "upnp device", "upnp control point"),
    5060: ("sip", "sip proxy / pbx", "sip endpoint"),
    5061: ("sips", "sip proxy / pbx", "sip endpoint"),
    102: ("s7comm", "s7 plc", "engineering / hmi station"),
    44818: ("ethernet-ip", "ethernet/ip device", "ethernet/ip scanner"),
    2404: ("iec104", "iec-104 outstation", "iec-104 master"),
    1962: ("plc-generic", "plc", "plc client"),
    4840: ("opcua", "opc ua server", "opc ua client"),
    18000: ("intouch", "scada server", "scada client"),
    3671: ("knx", "knx gateway", "knx client"),
    1911: ("niagara-fox", "building controller", "building workstation"),
    1433: ("mssql", "database server", "database client"),
    3306: ("mysql", "database server", "database client"),
    5432: ("postgresql", "database server", "database client"),
    1521: ("oracle-db", "database server", "database client"),
    139: ("netbios-ssn", "file / domain server", "domain member"),
    137: ("netbios-ns", "netbios name service", "netbios client"),
    548: ("afp", "file server", "file client"),
    2049: ("nfs", "file server", "file client"),
    111: ("rpcbind", "rpc server", "rpc client"),
    5355: ("llmnr", "llmnr responder", "llmnr responder"),
    67: ("dhcp", "dhcp server", "dhcp client"),
    68: ("dhcp", "dhcp client", "dhcp client"),
    69: ("tftp", "tftp server", "tftp client"),
    515: ("lpd", "printer", "print client"),
    8080: ("http-alt", "web server", "web client"),
    8443: ("https-alt", "web server", "web client"),
    1723: ("pptp", "vpn concentrator", "vpn client"),
    1812: ("radius", "radius server", "radius client"),
    3268: ("global-catalog", "domain controller", "domain member"),
    5985: ("winrm", "windows management endpoint", "management station"),
    5986: ("winrms", "windows management endpoint", "management station"),
    11111: ("dicom-alt", "pacs / image archive", "imaging modality"),
    2762: ("hl7-tls", "hl7 receiver", "hl7 sender"),
    4242: ("vitals-telemetry", "telemetry collector", "bedside device"),
}

# UDP ports where both ends legitimately use the same port (peer protocols).
# Sending to one of these does not indicate a client, and receiving on one does
# not indicate a server; both parties are peers.
UDP_PEER_PORTS = {47808, 5353, 5355, 137, 138, 123, 67, 68}

# Service markers that identify a network zone
ZONE_HINTS = {
    "ot": {"modbus", "bacnet", "dnp3", "s7comm", "ethernet-ip", "iec104",
           "opcua", "knx", "niagara-fox", "plc-generic", "intouch"},
    "clinical": {"dicom", "dicom-alt", "hl7-mllp", "hl7-tls",
                 "vitals-telemetry"},
    "it": {"ldap", "ldaps", "smb", "kerberos", "dns", "netbios-ssn",
           "global-catalog", "winrm", "winrms", "mssql", "rdp"},
    "iot": {"mqtt", "rtsp", "ssdp", "sip"},
}

# DNS-SD / mDNS service types mapped to the device class that advertises them.
# A service advertisement is a strong indicator of function: a host offering
# _ipp._tcp is a print service, whether or not it is a dedicated printer.
MDNS_SERVICE_TYPES = {
    "_ipp": ("printer", "print service"),
    "_ipps": ("printer", "print service"),
    "_printer": ("printer", "print service"),
    "_pdl-datastream": ("printer", "print service"),
    "_scanner": ("scanner", "scan service"),
    "_uscan": ("scanner", "scan service"),
    "_rtsp": ("camera / video source", "streaming service"),
    "_airplay": ("media device", "media receiver"),
    "_raop": ("media device", "audio receiver"),
    "_googlecast": ("media device", "media receiver"),
    "_spotify-connect": ("media device", "media receiver"),
    "_sftp-ssh": ("server", "file transfer"),
    "_ssh": ("server", "remote shell"),
    "_smb": ("server", "file share"),
    "_afpovertcp": ("server", "file share"),
    "_nfs": ("server", "file share"),
    "_http": ("network appliance", "web interface"),
    "_https": ("network appliance", "web interface"),
    "_workstation": ("workstation", "workstation"),
    "_device-info": ("network appliance", "device info"),
    "_hap": ("iot device", "home automation"),
    "_homekit": ("iot device", "home automation"),
    "_dicom": ("imaging modality", "dicom service"),
    "_sip": ("voip endpoint", "voip service"),
    "_ptp": ("time source", "precision time"),
}

# Substrings that identify a device class from a free-text banner or
# description string. Matching is case-insensitive and first-match-wins, so
# more specific entries are listed before more general ones.
BANNER_DEVICE_HINTS = [
    ("patient monitor", "patient monitor"),
    ("infusion", "infusion pump"),
    ("ventilator", "ventilator"),
    ("dialysis", "dialysis machine"),
    ("ultrasound", "imaging modality"),
    ("anesthesia", "anaesthesia machine"),
    ("defibrillat", "defibrillator"),
    ("analyzer", "laboratory analyser"),
    ("analyser", "laboratory analyser"),
    ("laserjet", "printer"),
    ("officejet", "printer"),
    ("jetdirect", "printer"),
    ("printer", "printer"),
    ("scanner", "scanner"),
    ("camera", "camera / video source"),
    ("ip cam", "camera / video source"),
    ("axis", "camera / video source"),
    ("hikvision", "camera / video source"),
    ("nvr", "video recorder"),
    ("switch", "network switch"),
    ("router", "router"),
    ("firewall", "firewall"),
    ("access point", "wireless access point"),
    ("ios software", "network switch"),
    ("ios-xe", "network switch"),
    ("procurve", "network switch"),
    ("powerconnect", "network switch"),
    ("catalyst", "network switch"),
    ("ups", "ups"),
    ("pdu", "power distribution unit"),
    ("thermostat", "hvac controller"),
    ("controller", "controller"),
    ("gateway", "gateway"),
    ("phone", "voip endpoint"),
    ("smart-tv", "media device"),
    ("smart tv", "media device"),
    ("television", "media device"),
]

# Free-text descriptions frequently name the operating system outright. Where
# a device states its own software in an LLDP description, an SNMP sysDescr or
# a CDP version string, that is a direct statement of identity and outranks any
# inference drawn from a stack signature.
BANNER_OS_HINTS = [
    ("ios-xe", "Cisco IOS XE"),
    ("cisco ios", "Cisco IOS"),
    ("cisco nx-os", "Cisco NX-OS"),
    ("nx-os", "Cisco NX-OS"),
    ("junos", "Junos"),
    ("arubaos", "ArubaOS"),
    ("comware", "HP Comware"),
    ("procurve", "HP ProCurve"),
    ("routeros", "RouterOS"),
    ("fortios", "FortiOS"),
    ("pan-os", "PAN-OS"),
    ("screenos", "ScreenOS"),
    ("vxworks", "VxWorks"),
    ("qnx", "QNX"),
    ("freertos", "FreeRTOS"),
    ("windows ce", "Windows CE"),
    ("windows", "Windows"),
    ("freebsd", "FreeBSD"),
    ("netbsd", "NetBSD"),
    ("openbsd", "OpenBSD"),
    ("solaris", "Solaris"),
    ("sunos", "Solaris"),
    ("aix", "AIX"),
    ("android", "Android"),
    ("linux", "Linux"),
]

# Device classes that identify purpose-built network or embedded hardware.
# A host in one of these classes is not a general-purpose server, which is
# sufficient to resolve a TTL-255 signature that is otherwise ambiguous.
EMBEDDED_DEVICE_CLASSES = {
    "network switch", "router", "firewall", "wireless access point",
    "printer", "camera / video source", "video recorder", "ups",
    "power distribution unit", "hvac controller", "controller", "gateway",
    "voip endpoint", "patient monitor", "infusion pump", "ventilator",
    "dialysis machine", "imaging modality", "laboratory analyser",
    "bacnet controller", "plc", "media device", "scanner", "iot device",
}


# SSH banners embed the distribution, which narrows the operating system
# beyond what a TCP signature alone can establish.
SSH_OS_HINTS = [
    ("ubuntu", "Linux (Ubuntu)"),
    ("debian", "Linux (Debian)"),
    ("raspbian", "Linux (Raspbian)"),
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("netbsd", "NetBSD"),
    ("sun_ssh", "Solaris"),
    ("dropbear", "embedded Linux"),
    ("cisco", "Cisco IOS"),
    ("mikrotik", "RouterOS"),
    ("windows", "Windows"),
]

# Services that corroborate an industrial (rather than Unix) TTL-255 stack
OT_SERVICES = {"modbus", "bacnet", "dnp3"}
UNIX_SERVICES = {"ssh", "ldap", "smb", "dns", "syslog"}


# ---------------------------------------------------------------------------
def first(val):
    """tshark emits comma-separated values when a field repeats in one frame
    (tunnels, multiple IP layers). Take the first occurrence."""
    return val.split(",")[0] if val else ""


def tsh(pcap, fields, dfilter=None, limit=None):
    """One tshark field-extraction pass; yields padded row lists.

    `limit` caps the number of rows consumed and terminates tshark early. It is
    intended for passes that read packet payloads, where the volume of data is
    large but the information sought is static: a host states the same
    application name in every message it sends, so a sample establishes it as
    well as the full set would. Passes that must see every packet, such as
    inventory and timing, leave the limit unset.
    """
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=\t"]
    if dfilter:
        cmd += ["-Y", dfilter]
    for f in fields:
        cmd += ["-e", f]

    n = len(fields)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        sys.exit("ERROR: tshark not found.  sudo apt install tshark")

    produced = 0
    try:
        for line in proc.stdout:
            if not line.strip():
                continue
            row = line.rstrip("\n").split("\t")
            yield (row + [""] * n)[:n]
            produced += 1
            if limit is not None and produced >= limit:
                # Stop by closing the pipe rather than by signalling tshark.
                # Closing stdout causes it to receive SIGPIPE on its next
                # write and exit. Signalling it directly can be refused where
                # tshark runs under a confinement policy that mediates
                # signals, which would abort the pass instead of ending it.
                break
    finally:
        # Closing the pipe stops tshark by way of SIGPIPE on its next write.
        # This is preferred over signalling the process directly, because
        # tshark may run with elevated privileges, in which case an unprivileged
        # caller is not permitted to signal it and terminate() raises
        # PermissionError.
        try:
            proc.stdout.close()
        except Exception:                             # noqa: BLE001
            pass
        if proc.poll() is None:
            try:
                proc.terminate()
            except (PermissionError, ProcessLookupError, OSError):
                pass
        err = ""
        try:
            err = proc.stderr.read() or ""
            proc.stderr.close()
        except Exception:                             # noqa: BLE001
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except (PermissionError, ProcessLookupError, OSError):
                pass
        if produced == 0 and proc.returncode not in (0, None) and err.strip():
            print(f"  ! tshark pass failed ({fields[:2]}...): "
                  f"{err.strip()[:300]}", file=sys.stderr)


class Inventory:
    def __init__(self):
        self.assets = defaultdict(lambda: {
            "ips": set(), "vlans": set(), "first": None, "last": None,
            "packets": 0, "serves": set(), "consumes": set(),
        })
        self.evidence = []                       # [mac, attr, val, src, tier, n]
        self._seen = {}                          # dedupe key -> evidence index
        self._index = defaultdict(list)          # (mac, attr) -> [indices]
        self.ip2mac = {}

    def touch(self, mac, ts=None):
        a = self.assets[mac]
        if ts is not None:
            a["first"] = ts if a["first"] is None else min(a["first"], ts)
            a["last"] = ts if a["last"] is None else max(a["last"], ts)
        return a

    def add(self, mac, attr, value, source, tier):
        """Record an observation.

        An identical observation from the same source increments a counter
        rather than creating a second record, since repetition is
        corroboration rather than new information.
        """
        if not mac or value in (None, "", "unknown"):
            return
        key = (mac, attr, str(value), source)
        if key in self._seen:
            self.evidence[self._seen[key]][5] += 1
            return
        idx = len(self.evidence)
        self._seen[key] = idx
        self.evidence.append([mac, attr, str(value), source, tier, 1])
        self._index[(mac, attr)].append(idx)      # O(1) lookup later

    def add_by_ip(self, ip, attr, value, source, tier):
        mac = self.ip2mac.get(ip)
        if mac:
            self.add(mac, attr, value, source, tier)

    def drop(self, mac, attr, value_prefix):
        """Retire evidence superseded by a better-informed conclusion.

        Records are tombstoned rather than deleted, so the observation history
        is preserved while being excluded from resolution.
        """
        keep = []
        for i in self._index.get((mac, attr), []):
            if not self.evidence[i][2].startswith(value_prefix):
                keep.append(i)
            else:
                self.evidence[i][4] = -1          # tombstone; excluded by resolve
        self._index[(mac, attr)] = keep

    def cands(self, mac, attr):
        return [self.evidence[i] for i in self._index.get((mac, attr), [])
                if self.evidence[i][4] >= 0]

    def resolve(self, mac, attr):
        """Select the best value for an attribute.

        Ranking is by tier first and observation count second. Where several
        independent sources report the same value, confidence is raised
        accordingly.
        """
        c = self.cands(mac, attr)
        if not c:
            return None, 0.0, ""
        c.sort(key=lambda e: (e[4], e[5]), reverse=True)
        best = c[0]
        agree = {e[3] for e in c if e[2] == best[2]}
        conf = min(0.99, best[4] + 0.05 * (len(agree) - 1))
        return best[2], conf, best[3]

    def values(self, mac, attr):
        return {e[2] for e in self.cands(mac, attr)}

    def conflicts(self, mac, attr):
        v = self.values(mac, attr)
        return sorted(v) if len(v) > 1 else []


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------

def pass_inventory(pcap, inv):
    """Every frame: MAC presence, OUI vendor, VLAN, IP binding, activity span."""
    n = 0
    for ts, mac, resolved, vlan, ip, _ttl in tsh(
            pcap, ["frame.time_epoch", "eth.src", "eth.src_resolved",
                   "vlan.id", "ip.src", "ip.ttl"]):
        mac = first(mac).lower()
        if not mac or mac.startswith(("01:", "33:33")) or mac == "ff:ff:ff:ff:ff:ff":
            continue                              # multicast/broadcast is not a host
        n += 1
        try:
            tsf = float(first(ts))
        except ValueError:
            tsf = None
        a = inv.touch(mac, tsf)
        a["packets"] += 1
        if vlan:
            a["vlans"].add(first(vlan))
        ip = first(ip)
        if ip:
            a["ips"].add(ip)
            inv.ip2mac.setdefault(ip, mac)
        # OUI vendor. tshark resolves the registered organisation. Registrants
        # are legal entities and may predate acquisitions or rebrands, so this
        # name can differ from the vendor's current trading name.
        resolved = first(resolved)
        if resolved and "_" in resolved:
            vendor = resolved.rsplit("_", 1)[0]
            if vendor and not re.fullmatch(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){2}",
                                           vendor):
                inv.add(mac, "vendor", vendor, "oui-registry", T2)
    print(f"  inventory      {n:>8} frames -> {len(inv.assets)} MACs")


def _parse_tcp_options(opt_hex):
    """Decode the TCP options blob -> (wscale, has_timestamps, has_sack)."""
    wscale, has_ts, has_sack = None, False, False
    try:
        b = binascii.unhexlify(first(opt_hex).replace(":", ""))
    except (binascii.Error, ValueError, TypeError):
        return wscale, has_ts, has_sack
    i = 0
    while i < len(b):
        kind = b[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        ln = b[i + 1]
        if ln < 2:
            break
        if kind == 3 and i + 2 < len(b):
            wscale = b[i + 2]
        elif kind == 8:
            has_ts = True
        elif kind == 4:
            has_sack = True
        i += ln
    return wscale, has_ts, has_sack


def _initial_ttl(ttl):
    for base in (32, 64, 128, 255):
        if ttl <= base:
            return base
    return 255


def pass_tcp_stack(pcap, inv):
    """Everything derivable from TCP handshake packets, in a single file read.

    Stack fingerprinting, service direction and connection timing all draw on
    SYN and SYN-ACK packets. Reading the capture once and deriving all three
    is substantially cheaper than three separate passes, because the cost of a
    pass is dominated by reading and dissecting the file rather than by the
    filter applied to it.
    """
    seen = 0
    attempts = 0
    convs = defaultdict(list)

    for ts, src, dst, ttl, win, opts, ack, dport in tsh(
            pcap, ["frame.time_epoch", "ip.src", "ip.dst", "ip.ttl",
                   "tcp.window_size_value", "tcp.options", "tcp.flags.ack",
                   "tcp.dstport"], "tcp.flags.syn==1"):
        src, dst, ttl, win = first(src), first(dst), first(ttl), first(win)
        if not (src and ttl and win):
            continue
        try:
            ttl_i, win_i = int(ttl), int(win)
        except ValueError:
            continue
        seen += 1
        # tshark renders boolean flag fields as "True"/"False" rather than
        # "1"/"0". Both spellings are accepted so that a change in rendering
        # cannot silently invert the direction of every handshake, which would
        # attribute each client's ephemeral port to it as a served service.
        is_synack = first(ack).lower() in ("1", "true")
        direction = "syn-ack" if is_synack else "syn"
        init_ttl = _initial_ttl(ttl_i)
        wscale, has_ts, has_sack = _parse_tcp_options(opts)

        sig = (init_ttl, win_i, wscale, has_ts, has_sack)
        if sig in STACK_SIGS:
            os_name, dtype = STACK_SIGS[sig]
            inv.add_by_ip(src, "os", os_name, f"tcp-stack-exact/{direction}", T3)
            inv.add_by_ip(src, "device_type_hint", dtype,
                          f"tcp-stack-exact/{direction}", T4)
        else:
            # Family fallback. Window sizes vary with kernel tuning, NIC
            # offload and intervening middleboxes, so exact matches are the
            # exception outside controlled conditions.
            if init_ttl == 255:
                fam = AMBIGUOUS_TTL255
            elif init_ttl == 128:
                fam = "Windows family"
            elif init_ttl == 64 and has_ts and (wscale or 0) >= 5:
                fam = "Linux / BSD family"
            elif init_ttl == 64:
                fam = "embedded / minimal stack"
            elif init_ttl == 32:
                fam = "legacy / minimal stack (TTL 32)"
            else:
                fam = None
            if fam:
                inv.add_by_ip(src, "os", fam, f"tcp-stack-family/{direction}", T4)

        # The raw signature is recorded whether or not it matched a table
        # entry. An unmatched signature that has been captured can still be
        # resolved later; one that was discarded cannot.
        inv.add_by_ip(src, "stack_raw",
                      f"ttl={init_ttl},win={win_i},ws={wscale},"
                      f"ts={int(has_ts)},sack={int(has_sack)}",
                      f"tcp-stack/{direction}", T2)
        inv.add_by_ip(src, "hops_from_sensor", init_ttl - ttl_i, "ttl-delta", T3)

        # An initial SYN identifies the connection's direction: the sender is
        # the client and the destination is the server.
        if is_synack:
            continue
        dport = first(dport)
        if not (dst and dport):
            continue
        attempts += 1
        port = int(dport)
        if port >= EPHEMERAL_PORT_FLOOR:
            # A connection to a high port is not evidence that the destination
            # offers a service there. Recording it would fill the inventory
            # with one entry per connection and swamp the real services.
            continue
        if (cm := inv.ip2mac.get(src)):
            inv.assets[cm]["consumes"].add(port)
        if (sm := inv.ip2mac.get(dst)):
            inv.assets[sm]["serves"].add(port)
        try:
            convs[(src, dst, dport)].append(float(first(ts)))
        except ValueError:
            pass

    _record_timing(inv, convs)
    print(f"  tcp-handshake  {seen:>8} SYN/SYN-ACK, {attempts} connections, "
          f"{len(convs)} conversation pairs")


def _record_timing(inv, convs):
    """Classify conversation regularity from connection inter-arrival times.

    Industrial traffic tends to be deterministic and general-purpose IT traffic
    bursty, so the coefficient of variation of the gaps between connections is
    a role indicator that is independent of payload content.
    """
    for (src, _dst, dport), times in convs.items():
        if len(times) < 8:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        mac = inv.ip2mac.get(src)
        if not mac:
            continue
        if cv < 0.15:
            inv.add(mac, "behaviour",
                    f"deterministic poller (~{mean:.2f}s, cv={cv:.3f})",
                    f"timing/port-{dport}", T3)
            inv.add(mac, "role_hint", "cyclic master / telemetry source",
                    f"timing/port-{dport}", T4)
        elif cv > 0.6:
            inv.add(mac, "behaviour", f"bursty (~{mean:.1f}s, cv={cv:.2f})",
                    f"timing/port-{dport}", T4)


def pass_ip_stack(pcap, inv):
    """OS inference from the IP header alone: TTL, DF, IP-ID behaviour.

    Covers UDP-only devices, which TCP fingerprinting cannot reach.

    Multicast traffic is excluded. Several discovery protocols mandate a TTL
    unrelated to the sending operating system: RFC 6762 requires 255 for mDNS,
    while SSDP uses a small value to scope its announcements. Including either
    would distort the initial-TTL estimate for every host that speaks them.
    """
    ttls, dfs, ids = defaultdict(list), defaultdict(list), defaultdict(list)
    for ip, ttl, df, ipid in tsh(
            pcap, ["ip.src", "ip.ttl", "ip.flags.df", "ip.id"],
            "ip && !tcp && !(ip.dst >= 224.0.0.0 && ip.dst <= 239.255.255.255)"):
        ip, ttl = first(ip), first(ttl)
        if not (ip and ttl):
            continue
        try:
            ttls[ip].append(int(ttl))
        except ValueError:
            continue
        dfs[ip].append(first(df) == "True")
        raw = first(ipid)
        if raw:
            try:
                ids[ip].append(int(raw, 16) if raw.startswith("0x") else int(raw))
            except ValueError:
                pass

    named = 0
    for ip, tl in ttls.items():
        ttl = max(set(tl), key=tl.count)
        init_ttl = _initial_ttl(ttl)
        df = max(set(dfs[ip]), key=dfs[ip].count) if dfs[ip] else False

        seq = ids.get(ip, [])
        if not seq:
            mode = "unknown"
        elif all(i == 0 for i in seq):
            mode = "zero"
        elif len(set(seq)) == 1:
            mode = "constant"
        elif len(seq) > 2 and all(0 < b - a <= 16 for a, b in zip(seq, seq[1:])):
            mode = "incrementing"
        else:
            mode = "random"

        inv.add_by_ip(ip, "ip_stack_raw",
                      f"ttl={init_ttl},df={int(df)},ipid={mode}", "ip-header", T2)
        inv.add_by_ip(ip, "hops_from_sensor", init_ttl - ttl, "ttl-delta", T3)

        name = IP_SIGS.get((init_ttl, df, mode))
        if name:
            inv.add_by_ip(ip, "os", name, "ip-header-exact", T4)
            named += 1
        else:
            fam = {255: AMBIGUOUS_TTL255,
                   128: "Windows family",
                   64: "Linux / embedded family",
                   32: "legacy / minimal stack (TTL 32)"}.get(init_ttl)
            if fam:
                inv.add_by_ip(ip, "os", fam, "ip-header-family", T4)
                named += 1
    print(f"  ip-stack       {len(ttls):>8} IP hosts -> {named} OS inferred")


def pass_services(pcap, inv):
    """Resolve UDP service direction and convert observed ports into roles.

    UDP has no handshake, so direction is taken from the source port. A host
    sending from a well-known port is answering on that service, while a host
    sending to it from an ephemeral port is a client. Ports where both ends
    legitimately use the same number are treated as peers rather than as a
    client and server pair. TCP direction is established during the handshake
    pass.
    """
    for src, sport, dport in tsh(pcap, ["ip.src", "udp.srcport", "udp.dstport"],
                                 "udp"):
        src, sport, dport = first(src), first(sport), first(dport)
        if not (src and sport and dport):
            continue
        mac = inv.ip2mac.get(src)
        if not mac:
            continue
        sp, dp = int(sport), int(dport)
        if sp in UDP_PEER_PORTS and dp == sp:
            inv.assets[mac]["serves"].add(sp)
        elif sp in PORT_ROLES and sp < 1024:
            inv.assets[mac]["serves"].add(sp)
        elif dp in PORT_ROLES:
            inv.assets[mac]["consumes"].add(dp)

    for mac, a in inv.assets.items():
        for port in a["serves"]:
            if port in PORT_ROLES:
                svc, srole, _ = PORT_ROLES[port]
                inv.add(mac, "service", svc, f"port-{port}/server", T3)
                inv.add(mac, "role", srole, f"port-{port}/server", T3)
        for port in a["consumes"]:
            if port in PORT_ROLES and port not in a["serves"]:
                svc, _, crole = PORT_ROLES[port]
                inv.add(mac, "role", crole, f"port-{port}/client", T3)
    print("  services       roles derived from observed port direction")


def _banner_os(text):
    """Extract an operating system name from a free-text description."""
    low = (text or "").lower()
    for needle, os_name in BANNER_OS_HINTS:
        if needle in low:
            return os_name
    return None


def _banner_device_type(text):
    """Map a free-text banner or description to a device class, if one matches."""
    low = (text or "").lower()
    for needle, dtype in BANNER_DEVICE_HINTS:
        if needle in low:
            return dtype
    return None


def pass_infrastructure(pcap, inv):
    """Link-layer discovery protocols, which describe network structure.

    LLDP and CDP are periodic announcements in which switches, routers, access
    points and IP phones state their own identity, model, software version and
    the physical port an endpoint is attached to. STP participation identifies
    a switch, and its root bridge identifier describes the layer 2 topology.
    VRRP identifies a redundant gateway. All are read in one pass, since the
    cost of a pass is dominated by reading the capture rather than by the
    filter applied to it.
    """
    c = defaultdict(int)
    dfilter = "lldp || cdp || stp || vrrp"
    fields = ["eth.src", "ip.src",
              "lldp.tlv.system.name", "lldp.tlv.system.desc",
              "lldp.port.id", "lldp.port.desc",
              "cdp.deviceid", "cdp.platform", "cdp.software_version",
              "cdp.portid", "stp.root.hw", "vrrp.virt_rtr_id"]

    for row in tsh(pcap, fields, dfilter, limit=ANNOUNCEMENT_SAMPLE_LIMIT):
        (mac, ip, sysname, sysdesc, portid, portdesc,
         devid, platform, version, cdp_port, stp_root, vrid) = row
        mac = first(mac).lower()

        if mac and (sysname or sysdesc):
            c["lldp"] += 1
            if sysname:
                inv.add(mac, "hostname", first(sysname), "lldp-system-name", T1)
            if sysdesc:
                inv.add(mac, "software", sysdesc[:120], "lldp-system-desc", T1)
                if (dt := _banner_device_type(sysdesc)):
                    inv.add(mac, "device_type", dt, "lldp-system-desc", T1)
                if (osn := _banner_os(sysdesc)):
                    inv.add(mac, "os", osn, "lldp-system-desc", T1)
                if sysdesc.split():
                    inv.add(mac, "vendor", sysdesc.split()[0],
                            "lldp-system-desc", T2)
            if portid:
                inv.add(mac, "switch_port", first(portid), "lldp-port-id", T1)
            if portdesc:
                inv.add(mac, "switch_port_desc", portdesc[:60],
                        "lldp-port-desc", T1)

        if mac and (devid or platform):
            c["cdp"] += 1
            if devid:
                inv.add(mac, "hostname", first(devid), "cdp-device-id", T1)
            if platform:
                inv.add(mac, "model", first(platform), "cdp-platform", T1)
                if (dt := _banner_device_type(platform)):
                    inv.add(mac, "device_type", dt, "cdp-platform", T1)
            if version:
                inv.add(mac, "software", version[:120],
                        "cdp-software-version", T1)
                if (osn := _banner_os(version)):
                    inv.add(mac, "os", osn, "cdp-software-version", T1)
                if version.split():
                    inv.add(mac, "vendor", version.split()[0],
                            "cdp-software-version", T2)
            if cdp_port:
                inv.add(mac, "switch_port", first(cdp_port), "cdp-port-id", T1)

        if mac and stp_root:
            c["stp"] += 1
            inv.add(mac, "device_type", "network switch", "stp-participant", T3)
            if first(stp_root).lower() == mac:
                inv.add(mac, "role", "spanning tree root bridge", "stp-root", T2)

        if vrid and (ip := first(ip)):
            c["vrrp"] += 1
            inv.add_by_ip(ip, "role", "redundant gateway", "vrrp", T2)
            inv.add_by_ip(ip, "device_type", "router", "vrrp", T3)

    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  infrastructure {summary if summary else 'none found'}")


def pass_clinical(pcap, inv):
    """Protocols specific to clinical environments.

    DICOM association requests carry Application Entity titles, which are the
    names imaging equipment and archives use to address one another. HL7
    messages carry sending and receiving application and facility identifiers
    in the MSH segment. Both are configured per site and identify the system
    rather than the host, so they are recorded as self-declared evidence.
    """
    c = defaultdict(int)

    for ip, dst, calling, called, uid, version in tsh(
            pcap, ["ip.src", "ip.dst", "dicom.assoc.ae.calling",
                   "dicom.assoc.ae.called", "dicom.userinfo.uid",
                   "dicom.userinfo.version"], "dicom",
            limit=PAYLOAD_SAMPLE_LIMIT):
        ip, dst = first(ip), first(dst)
        calling, called = first(calling).strip(), first(called).strip()
        if ip and calling:
            inv.add_by_ip(ip, "ae_title", calling, "dicom-calling-ae", T1)
            inv.add_by_ip(ip, "device_type", "imaging modality",
                          "dicom-calling-ae", T2)
            c["dicom"] += 1
        if dst and called:
            # The called AE title names the peer, so it is attributed to the
            # destination host rather than to the sender.
            inv.add_by_ip(dst, "ae_title", called, "dicom-called-ae", T1)
            inv.add_by_ip(dst, "device_type", "pacs / image archive",
                          "dicom-called-ae", T2)
        if ip and version:
            inv.add_by_ip(ip, "software", first(version),
                          "dicom-implementation-version", T1)
        if ip and uid:
            inv.add_by_ip(ip, "dicom_impl_uid", first(uid),
                          "dicom-implementation-uid", T2)

    # HL7 identifiers live in the pipe-delimited MSH segment, which has no
    # dedicated dissector fields, so the segment is read from the payload.
    for ip, dst, payload in tsh(pcap, ["ip.src", "ip.dst", "tcp.payload"],
                                "hl7", limit=PAYLOAD_SAMPLE_LIMIT):
        ip, dst, payload = first(ip), first(dst), first(payload)
        if not (ip and payload):
            continue
        try:
            txt = binascii.unhexlify(payload.replace(":", "")).decode(
                "utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        for line in txt.splitlines():
            stripped = line.lstrip("\x0b")
            if not stripped.startswith("MSH"):
                continue
            f = stripped.split("|")
            if len(f) > 3 and f[2]:
                inv.add_by_ip(ip, "application", f[2].strip(),
                              "hl7-msh-sending-application", T1)
                c["hl7"] += 1
            if len(f) > 3 and f[3]:
                inv.add_by_ip(ip, "facility", f[3].strip(),
                              "hl7-msh-sending-facility", T1)
            if dst and len(f) > 5 and f[4]:
                inv.add_by_ip(dst, "application", f[4].strip(),
                              "hl7-msh-receiving-application", T1)
            break

    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  clinical       {summary if summary else 'none found'}")


def pass_industrial(pcap, inv):
    """Industrial protocols that carry explicit device identity.

    EtherNet/IP and CIP Identity responses contain vendor, product name,
    product code, revision and serial number. S7 and IEC-104 traffic identifies
    the role of each endpoint from the direction of the exchange.
    """
    c = defaultdict(int)

    for ip, vendor, product, serial, dtype, major, minor in tsh(
            pcap, ["ip.src", "cip.id.vendor_id", "cip.id.product_name",
                   "cip.id.serial_number", "cip.id.device_type",
                   "cip.id.major_rev", "cip.id.minor_rev"], "cip",
            limit=PAYLOAD_SAMPLE_LIMIT):
        ip = first(ip)
        if not ip:
            continue
        if product:
            inv.add_by_ip(ip, "model", first(product), "cip-identity", T1)
            c["cip"] += 1
            if (dt := _banner_device_type(product)):
                inv.add_by_ip(ip, "device_type", dt, "cip-identity", T1)
        if vendor:
            inv.add_by_ip(ip, "vendor_id_raw", first(vendor), "cip-identity", T1)
        if serial:
            inv.add_by_ip(ip, "serial_number", first(serial), "cip-identity", T1)
        if dtype:
            inv.add_by_ip(ip, "device_type_raw", first(dtype), "cip-identity", T1)
        if major:
            rev = first(major) + ("." + first(minor) if minor else "")
            inv.add_by_ip(ip, "firmware", rev, "cip-identity", T1)

    for ip, rosctr, iec_type in tsh(
            pcap, ["ip.src", "s7comm.header.rosctr", "iec60870_asdu.typeid"],
            "s7comm || iec60870_asdu", limit=PAYLOAD_SAMPLE_LIMIT):
        ip = first(ip)
        if not ip:
            continue
        if rosctr:
            inv.add_by_ip(ip, "service", "s7comm", "s7comm-traffic", T3)
            c["s7comm"] += 1
        if iec_type:
            inv.add_by_ip(ip, "service", "iec104", "iec104-traffic", T3)
            c["iec104"] += 1

    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  industrial     {summary if summary else 'none found'}")


def pass_tls(pcap, inv):
    """TLS handshake metadata.

    Server certificates are presented in the clear during the handshake. The
    subject common name is chosen by whoever provisioned the device and on
    embedded equipment frequently contains the model or serial number. The JA3
    hash summarises client hello parameters and characterises the TLS library
    rather than the host, so it is recorded as a raw attribute rather than
    resolved to a product.
    """
    c = defaultdict(int)

    for ip, cn, san in tsh(
            pcap, ["ip.src", "x509sat.printableString", "x509ce.dNSName"],
            "tls.handshake.type==11", limit=PAYLOAD_SAMPLE_LIMIT):
        ip, cn, san = first(ip), first(cn), first(san)
        if ip and cn:
            inv.add_by_ip(ip, "cert_subject", cn[:80], "tls-certificate", T1)
            c["cert"] += 1
            if (dt := _banner_device_type(cn)):
                inv.add_by_ip(ip, "device_type", dt, "tls-certificate", T2)
        if ip and san:
            inv.add_by_ip(ip, "cert_san", san[:80], "tls-certificate-san", T1)

    for ip, sni, ja3 in tsh(
            pcap, ["ip.src", "tls.handshake.extensions_server_name",
                   "tls.handshake.ja3"],
            "tls.handshake.type==1", limit=PAYLOAD_SAMPLE_LIMIT):
        ip, sni, ja3 = first(ip), first(sni), first(ja3)
        if ip and sni:
            inv.add_by_ip(ip, "tls_sni_requested", sni[:80], "tls-sni", T2)
        if ip and ja3:
            inv.add_by_ip(ip, "ja3", ja3, "tls-client-hello", T2)
            c["ja3"] += 1

    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  tls            {summary if summary else 'none found'}")


def _bacnet_vendor_names(pcap, inv):
    """Resolve numeric BACnet vendor identifiers to organisation names.

    Vendor IDs are numeric on the wire. Wireshark resolves them against the
    ASHRAE registry, so reading its output avoids maintaining a separate copy
    that would fall out of date. The value is self-declared evidence, as the
    device states its own manufacturer.
    """
    try:
        out = subprocess.run(
            ["tshark", "-r", pcap, "-Y", "bacapp.unconfirmed_service==0", "-V"],
            capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return
    ip = None
    for line in out.stdout.splitlines():
        if (m := re.search(r"Source Address:\s*([\d.]+)", line)):
            ip = m.group(1)
        elif (m := re.search(r"Vendor ID:\s*(.+?)\s*\((\d+)\)", line)) and ip:
            inv.add_by_ip(ip, "vendor", m.group(1).strip(), "bacnet-vendor-id", T1)


def pass_selfdeclared(pcap, inv):
    """Tier 1 evidence, in which a device states its own identity.

    Several protocols are read in a single pass with a combined filter and the
    union of their fields, then dispatched on whichever fields are populated.
    The cost of a pass is dominated by reading and dissecting the capture
    rather than by the filter applied to it, so one combined read is markedly
    cheaper than one read per protocol.
    """
    c = defaultdict(int)

    dfilter = ("dhcp || (mdns && dns.flags.response==1) "
               "|| bacapp.unconfirmed_service==0 || ipp "
               "|| (tcp && http.server) || (tcp && http.user_agent) "
               "|| ldap.name || smb2.dialect")
    fields = ["eth.src", "ip.src",
              "dhcp.option.hostname", "dhcp.option.vendor_class_id",
              "dhcp.option.request_list_item",
              "dns.resp.name", "dns.ptr.domain_name",
              "bacapp.instance_number", "bacapp.vendor_identifier",
              "ipp.name", "ipp.charstring_value",
              "http.server", "http.user_agent",
              "ldap.name", "smb2.dialect"]

    for row in tsh(pcap, fields, dfilter):
        (mac, ip, dhcp_host, dhcp_vclass, dhcp_plist, resp_name, ptr_name,
         bac_inst, bac_vid, ipp_names, ipp_vals, http_server, http_ua,
         ldap_dn, smb_dialect) = row
        mac = first(mac).lower()
        ip = first(ip)

        if dhcp_host or dhcp_vclass or dhcp_plist:
            if dhcp_host:
                inv.add(mac, "hostname", first(dhcp_host), "dhcp-hostname", T1)
                c["dhcp"] += 1
            if dhcp_vclass:
                inv.add(mac, "vendor_class", first(dhcp_vclass),
                        "dhcp-vendor-class", T2)
            if dhcp_plist:
                inv.add(mac, "dhcp_fingerprint", dhcp_plist.replace(",", "-"),
                        "dhcp-option55", T2)

        if ip and resp_name:
            host = first(resp_name).replace(".local", "").strip(".")
            # Records beginning with an underscore are DNS-SD service types
            # rather than host names, and are handled by service discovery.
            if host and not host.startswith("_") and "._" not in host:
                inv.add_by_ip(ip, "hostname", host, "mdns", T1)
                c["mdns"] += 1
            _harvest_service_types(inv, ip, (resp_name, ptr_name), c)

        if ip and bac_inst:
            inv.add_by_ip(ip, "bacnet_instance", first(bac_inst),
                          "bacnet-iam", T1)
            inv.add_by_ip(ip, "device_type", "bacnet controller",
                          "bacnet-iam", T1)
            c["bacnet"] += 1
        if ip and bac_vid:
            inv.add_by_ip(ip, "vendor_id_raw", first(bac_vid), "bacnet-iam", T1)

        if ip and ipp_names and ipp_vals:
            for name, value in zip(ipp_names.split(","), ipp_vals.split(",")):
                if name == "printer-make-and-model":
                    inv.add_by_ip(ip, "model", value, "ipp-attributes", T1)
                    inv.add_by_ip(ip, "device_type", "printer",
                                  "ipp-attributes", T1)
                    if value.split():
                        inv.add_by_ip(ip, "vendor", value.split()[0],
                                      "ipp-attributes", T1)
                    c["ipp"] += 1

        if ip and http_server:
            inv.add_by_ip(ip, "software", first(http_server),
                          "http-server-header", T2)
        if ip and http_ua:
            # User-Agent strings contain commas, so the value is kept intact.
            inv.add_by_ip(ip, "user_agent", http_ua[:60], "http-user-agent", T2)

        if ip and ldap_dn:
            # Distinguished names contain commas, so this field must not be
            # split on them.
            if (m := re.search(r"CN=([^,]+)", ldap_dn)):
                inv.add_by_ip(ip, "hostname", m.group(1), "ldap-bind-dn", T1)
            if (dcs := re.findall(r"DC=([^,]+)", ldap_dn)):
                inv.add_by_ip(ip, "domain", ".".join(dcs), "ldap-bind-dn", T1)
                c["ldap"] += 1

        if ip and smb_dialect:
            inv.add_by_ip(ip, "smb_dialect", first(smb_dialect), "smb2", T2)

    # RTSP identity lives in a response header with no dedicated field, so the
    # payload must be read. Kept separate because payload extraction is far
    # more expensive than field extraction.
    for ip, payload in tsh(pcap, ["ip.src", "tcp.payload"], "rtsp",
                           limit=PAYLOAD_SAMPLE_LIMIT):
        ip, payload = first(ip), first(payload)
        if not (ip and payload):
            continue
        try:
            txt = binascii.unhexlify(payload.replace(":", "")).decode(
                "utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if (m := re.search(r"Server:\s*([^\r\n]+)", txt)):
            inv.add_by_ip(ip, "software", m.group(1).strip(), "rtsp-banner", T1)
            inv.add_by_ip(ip, "device_type", "camera / video source",
                          "rtsp-banner", T1)
            c["rtsp"] += 1

    _bacnet_vendor_names(pcap, inv)

    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  self-declared  {summary if summary else 'none found'}")


def _harvest_service_types(inv, ip, blobs, counter):
    """Map DNS-SD service types to the device class that advertises them.

    The mapping is reliable but remains an inference from the service offered
    rather than a statement of identity, so it is filed one tier below a direct
    self-declaration.
    """
    for blob in blobs:
        for token in (blob or "").split(","):
            for part in token.split("."):
                if not part.startswith("_"):
                    continue
                if (hit := MDNS_SERVICE_TYPES.get(part.lower())):
                    dtype, svc = hit
                    inv.add_by_ip(ip, "device_type", dtype,
                                  f"mdns-service{part}", T2)
                    inv.add_by_ip(ip, "service", svc,
                                  f"mdns-service{part}", T2)
                    counter["mdns-sd"] += 1


def pass_banners(pcap, inv):
    """Text banners and management descriptions in which hosts name themselves.

    SSH, FTP, SMTP and Telnet servers announce their software on connection.
    SNMP sysDescr, SIP User-Agent headers and SSDP SERVER headers are equally
    explicit. These are among the most specific identifiers available
    passively, frequently naming the exact model and firmware revision. All are
    read in one pass and dispatched on whichever fields are populated.
    """
    c = defaultdict(int)

    dfilter = ("ssh.protocol || ftp.response || smtp.rsp.parameter "
               "|| sip.User-Agent || snmp.name || nbns.name "
               "|| (udp.port==1900 && http.server)")
    fields = ["ip.src", "udp.srcport",
              "ssh.protocol", "ftp.response.arg", "smtp.rsp.parameter",
              "sip.User-Agent", "snmp.name", "snmp.value.octets",
              "nbns.name", "http.server"]

    for row in tsh(pcap, fields, dfilter):
        (ip, usport, ssh_b, ftp_arg, smtp_param, sip_ua,
         snmp_oid, snmp_octets, nb_name, http_server) = row
        ip = first(ip)
        if not ip:
            continue

        if ssh_b:
            banner = first(ssh_b)
            inv.add_by_ip(ip, "software", banner, "ssh-banner", T1)
            c["ssh"] += 1
            low = banner.lower()
            for needle, os_name in SSH_OS_HINTS:
                if needle in low:
                    # The distribution string is stated by the host, but the
                    # mapping to an operating system is an inference from it.
                    inv.add_by_ip(ip, "os", os_name, "ssh-banner-distro", T2)
                    break
            if (dt := _banner_device_type(banner)):
                inv.add_by_ip(ip, "device_type", dt, "ssh-banner", T2)

        if ftp_arg and len(ftp_arg) > 4:
            inv.add_by_ip(ip, "software", ftp_arg[:100], "ftp-banner", T1)
            c["ftp"] += 1

        if smtp_param and len(smtp_param) > 8:
            inv.add_by_ip(ip, "software", smtp_param[:100], "smtp-banner", T1)
            c["smtp"] += 1

        if sip_ua:
            ua = first(sip_ua)
            inv.add_by_ip(ip, "software", ua, "sip-user-agent", T1)
            inv.add_by_ip(ip, "device_type", "voip endpoint",
                          "sip-user-agent", T2)
            c["sip"] += 1
            if "/" in ua:
                inv.add_by_ip(ip, "model", ua.split("/")[0],
                              "sip-user-agent", T1)
            if ua and not ua[0].isdigit():
                inv.add_by_ip(ip, "vendor", ua.split("-")[0].split("/")[0],
                              "sip-user-agent", T2)

        if snmp_oid and snmp_octets:
            _harvest_snmp(inv, ip, snmp_oid, snmp_octets, c)

        if nb_name:
            name = first(nb_name).split("<")[0].strip()
            if name:
                inv.add_by_ip(ip, "hostname", name, "netbios-name", T1)
                c["nbns"] += 1

        # An SSDP advertisement carries a SERVER header describing the
        # operating system and product, in the same form as an HTTP response.
        if http_server and first(usport) == "1900":
            inv.add_by_ip(ip, "software", http_server[:120],
                          "ssdp-server-header", T1)
            c["ssdp"] += 1
            if (dt := _banner_device_type(http_server)):
                inv.add_by_ip(ip, "device_type", dt, "ssdp-server-header", T1)
            if (osn := _banner_os(http_server)):
                inv.add_by_ip(ip, "os", osn, "ssdp-server-header", T1)

    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  banners        {summary if summary else 'none found'}")


def _harvest_snmp(inv, ip, oids, octets, counter):
    """Read the SNMP system group, which a device supplies about itself.

    Values arrive hex-encoded, and a single response may carry several
    bindings, so object identifiers and values are paired positionally.
    """
    for oid, value in zip(oids.split(","), octets.split(",")):
        if not oid.startswith("1.3.6.1.2.1.1."):
            continue
        try:
            text = bytes.fromhex(value.replace(":", "")).decode("utf-8",
                                                               "ignore").strip()
        except ValueError:
            continue
        if not text:
            continue
        if oid.startswith("1.3.6.1.2.1.1.1"):              # sysDescr
            inv.add_by_ip(ip, "software", text[:120], "snmp-sysdescr", T1)
            if (dt := _banner_device_type(text)):
                inv.add_by_ip(ip, "device_type", dt, "snmp-sysdescr", T1)
            if (osn := _banner_os(text)):
                inv.add_by_ip(ip, "os", osn, "snmp-sysdescr", T1)
            if text.split():
                inv.add_by_ip(ip, "vendor", text.split()[0],
                              "snmp-sysdescr", T2)
            counter["snmp"] += 1
        elif oid.startswith("1.3.6.1.2.1.1.5"):            # sysName
            inv.add_by_ip(ip, "hostname", text, "snmp-sysname", T1)
        elif oid.startswith("1.3.6.1.2.1.1.6"):            # sysLocation
            inv.add_by_ip(ip, "location", text, "snmp-syslocation", T1)


def protocol_census(pcap):
    """Return the set of protocol names present in the capture.

    A single protocol-hierarchy pass costs one read of the file and allows
    later passes to be skipped entirely when the protocols they parse are
    absent. On captures that use only part of the supported protocol set this
    is substantially cheaper than running every pass unconditionally.
    """
    try:
        out = subprocess.run(["tshark", "-r", pcap, "-q", "-z", "io,phs"],
                             capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    present = set()
    for line in out.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("=") or ":" not in stripped:
            continue
        name = stripped.split()[0]
        if re.fullmatch(r"[a-z0-9_.\-]+", name):
            present.add(name)
            present.add(name.split(".")[0])
    return present or None


# Protocols each optional pass depends on. A pass is skipped when none of its
# protocols appear in the capture. Passes absent from this mapping always run.
PASS_REQUIREMENTS = {
    "pass_infrastructure": {"lldp", "cdp", "stp", "vrrp"},
    "pass_clinical": {"dicom", "hl7"},
    "pass_industrial": {"cip", "enip", "s7comm", "iec60870_asdu"},
    "pass_banners": {"ssh", "ftp", "smtp", "sip", "snmp", "ssdp", "nbns"},
    "pass_tls": {"tls", "ssl"},
    "pass_selfdeclared": {"dhcp", "mdns", "bacapp", "ipp", "http", "rtsp",
                          "ldap", "smb2"},
}


def refine_ambiguous(inv):
    """Narrow deliberately ambiguous OS labels using independent evidence.

    TTL 255 is the default for industrial stacks and for Solaris and AIX alike,
    so the stack passes emit an ambiguous label that is resolved here.

    Order matters: stack richness is evaluated before service hints. A
    general-purpose operating system presents a feature-rich stack, with window
    scaling, SACK, timestamps and a large receive window, whereas an industrial
    stack is minimal. That property holds regardless of which application
    protocol the host happens to speak, which makes it the stronger of the two
    discriminators, since a general-purpose host can run an OT gateway.

    Where nothing corroborates a verdict, the ambiguous label is retained
    rather than resolved, so that the uncertainty is visible in the output.
    """
    resolved = 0
    for mac in list(inv.assets):
        if AMBIGUOUS_TTL255 not in inv.values(mac, "os"):
            continue

        raw = " ".join(inv.values(mac, "stack_raw"))
        win = int(m.group(1)) if (m := re.search(r"win=(\d+)", raw)) else None
        has_ws = "ws=None" not in raw and "ws=" in raw
        has_ts = "ts=1" in raw
        has_sack = "sack=1" in raw
        features = sum([has_ws, has_ts, has_sack])

        verdict, source, tier = None, None, None

        if win is not None:
            if features >= 2 and win >= 16384:
                # Rich stack: window scaling / SACK / timestamps and a large
                # receive window. Industrial stacks do not look like this.
                verdict, source, tier = ("Solaris / AIX family",
                                         "ttl255+feature-rich-stack", T3)
            elif features == 0 and win <= 8192:
                verdict, source, tier = ("VxWorks / industrial stack",
                                         "ttl255+minimal-stack", T3)

        if verdict is None:
            # No usable TCP signature, i.e. a UDP-only host. Speaking an OT
            # protocol is not sufficient on its own, since a general-purpose
            # host can run an OT gateway.
            #
            # A self-declared embedded device role is sufficient. A BACnet
            # I-Am announces "I am a BACnet device" together with a vendor ID,
            # whereas a Who-Is is a management query that any host can send,
            # so only the former identifies an embedded controller.
            declared = inv.values(mac, "device_type")
            if declared & EMBEDDED_DEVICE_CLASSES:
                # The host has identified itself as purpose-built hardware
                # rather than a general-purpose server, which excludes the
                # Solaris and AIX reading of a TTL-255 signature.
                verdict, source, tier = ("embedded / industrial stack",
                                         "ttl255+self-declared-device-class", T4)
            elif any("controller" in d or "plc" in d for d in declared):
                verdict, source, tier = ("VxWorks / industrial stack",
                                         "ttl255+self-declared-controller", T4)
            # Otherwise the ambiguous label is retained. A UDP-only TTL-255
            # host that declares nothing about itself cannot be separated from
            # the Solaris and AIX family on the available evidence.

        if verdict:
            inv.drop(mac, "os", AMBIGUOUS_TTL255)
            inv.add(mac, "os", verdict, source, tier)
            resolved += 1

    print(f"  refine         {resolved:>8} ambiguous OS labels narrowed")


def pass_zones(inv):
    """Infer a zone per VLAN from the protocol mix observed on it."""
    vlan_services = defaultdict(set)
    for mac, a in inv.assets.items():
        svcs = inv.values(mac, "service")
        for v in a["vlans"]:
            vlan_services[v] |= svcs

    vlan_zone = {}
    for vlan, svcs in vlan_services.items():
        best, score_ = None, 0
        for zone, markers in ZONE_HINTS.items():
            hit = len(svcs & markers)
            if hit > score_:
                best, score_ = zone, hit
        if best:
            vlan_zone[vlan] = best

    for mac, a in inv.assets.items():
        for v in a["vlans"]:
            if v in vlan_zone:
                inv.add(mac, "zone", vlan_zone[v], f"vlan-{v}-protocol-mix", T3)
    print(f"  zones          {len(vlan_zone):>8} VLANs classified")


# ---------------------------------------------------------------------------
ATTRS = ["hostname", "vendor", "model", "os", "device_type", "role", "service",
         "zone", "software", "firmware", "serial_number", "behaviour", "domain",
         "application", "facility", "ae_title", "location", "switch_port",
         "cert_subject", "cert_san", "ja3", "bacnet_instance",
         "dhcp_fingerprint", "stack_raw", "ip_stack_raw", "hops_from_sensor"]


def write_outputs(inv, assets_path, evidence_path):
    with open(assets_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["mac", "ips", "vlan", "packets", "first_seen", "last_seen",
                    "serves_ports", "consumes_ports"]
                   + [c for a in ATTRS for c in (a, a + "_conf")]
                   + ["conflicts"])
        for mac, a in sorted(inv.assets.items(), key=lambda kv: -kv[1]["packets"]):
            row = [mac, ";".join(sorted(a["ips"])), ";".join(sorted(a["vlans"])),
                   a["packets"],
                   f"{a['first']:.0f}" if a["first"] else "",
                   f"{a['last']:.0f}" if a["last"] else "",
                   ";".join(str(p) for p in sorted(a["serves"])),
                   ";".join(str(p) for p in sorted(a["consumes"]))]
            conflicts = []
            for attr in ATTRS:
                val, conf, _ = inv.resolve(mac, attr)
                row += [val or "", f"{conf:.2f}" if val else ""]
                if attr in ("os", "vendor", "hostname", "model"):
                    if (cf := inv.conflicts(mac, attr)):
                        conflicts.append(f"{attr}={len(cf)}")
            row.append(";".join(conflicts))
            w.writerow(row)

    with open(evidence_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["mac", "attribute", "value", "source", "tier", "tier_name",
                    "observations"])
        for mac, attr, val, src, tier, n in sorted(inv.evidence):
            if tier >= 0:
                w.writerow([mac, attr, val, src, tier, TIER_NAME.get(tier, ""), n])


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# OUI registrants are legal entities and often predate acquisitions, so a
# registry name and a current trading name may refer to the same hardware.
# These groups exist solely so that scoring can compare the two fairly. The
# extractor itself always reports the value it observed.
VENDOR_ALIASES = [
    {"hp", "hewlettpackard", "hewlettpacka", "hewlettpackardcompany"},
    {"schneiderelectric", "telemecanique", "telemecaniqu"},
    {"rockwellautomation", "rockwellauto", "allenbradley"},
    {"axiscommunications", "axis"},
    {"vmware", "vmwareinc"},
    {"siemens", "siemensag"},
    {"sun", "sunmicrosystems", "oracle"},
]

OS_EQUIV = {
    "windows 10/11": ["windows 10", "windows 11"],
    "windows server": ["windows server"],
    "windows family": ["windows"],
    "linux (modern kernel)": ["linux"],
    "linux / bsd family": ["linux", "bsd"],
    "linux / embedded family": ["linux", "embedded linux"],
    "embedded linux": ["embedded linux"],
    "embedded linux / rtos": ["embedded linux", "rtos"],
    "embedded rtos": ["rtos"],
    "vxworks / industrial stack": ["vxworks"],
    "solaris / aix family": ["solaris", "aix"],
    "cisco ios": ["cisco ios", "ios"],
    "cisco ios xe": ["cisco ios", "ios-xe"],
    "embedded / industrial stack": ["vxworks", "rtos", "embedded"],
    "printer firmware": ["printer firmware"],
}


def vendor_ok(found, truth):
    f, t = norm(found), norm(truth)
    if not f or not t:
        return False
    if f == t or f.startswith(t) or t.startswith(f):
        return True
    return any(f in g and t in g for g in VENDOR_ALIASES)


def os_ok(found, truth):
    if not found:
        return False
    f, t = found.lower(), (truth or "").lower()
    for pat in OS_EQUIV.get(f, [f]):
        if pat in t or t in pat:
            return True
    return False


def score(inv, truth_path):
    rows = list(csv.DictReader(open(truth_path)))
    tot, hit, misses = defaultdict(int), defaultdict(int), []
    ZONE_ALIAS = {"medical": "clinical"}

    for t in rows:
        mac = t["mac"].lower()
        tot["discovered"] += 1
        if mac not in inv.assets:
            misses.append((t["name"], "device", "NOT DISCOVERED", ""))
            continue
        hit["discovered"] += 1

        v, _, _ = inv.resolve(mac, "vendor")
        o, _, _ = inv.resolve(mac, "os")
        z, _, _ = inv.resolve(mac, "zone")
        got_vlan = ";".join(sorted(inv.assets[mac]["vlans"]))

        for attr, got, want, ok in [
            ("vendor", v, t["vendor"], vendor_ok(v, t["vendor"])),
            ("os", o, t["os"], os_ok(o, t["os"])),
            ("zone", z, t["zone"],
             bool(z) and z in (t["zone"], ZONE_ALIAS.get(t["zone"]))),
            ("vlan", got_vlan, t["vlan"], got_vlan == t["vlan"]),
        ]:
            tot[attr] += 1
            if ok:
                hit[attr] += 1
            else:
                misses.append((t["name"], attr, got or "(none)", want))

    print("\n" + "=" * 64)
    print("SCORE vs ground truth")
    print("=" * 64)
    for k in ["discovered", "vendor", "os", "zone", "vlan"]:
        if tot[k]:
            pct = 100 * hit[k] / tot[k]
            print(f"  {k:<12} {hit[k]:>3}/{tot[k]:<3} {pct:5.1f}%  "
                  f"{'#' * int(pct / 5)}")

    if (extra := set(inv.assets) - {r["mac"].lower() for r in rows}):
        print(f"\n  {len(extra)} MAC(s) not in ground truth: {sorted(extra)[:3]}")

    if misses:
        print(f"\n  {len(misses)} mismatches (showing up to 15):")
        print(f"  {'device':<22}{'attr':<9}{'extracted':<40}expected")
        for name, attr, got, want in misses[:15]:
            print(f"  {name:<22}{attr:<9}{str(got)[:38]:<40}{want}")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--assets", default="assets.csv")
    ap.add_argument("--evidence", default="evidence.csv")
    ap.add_argument("--score", help="ground_truth.csv to score against")
    ap.add_argument("--sample-limit", type=int, default=None,
                    help="Row cap for payload and announcement passes "
                         "(default 3000 and 2000 respectively). Raise it when "
                         "a value may appear only late in a long capture.")
    ap.add_argument("--all-passes", action="store_true",
                    help="Run every pass regardless of which protocols the "
                         "capture contains. Slower, but useful if a dissector "
                         "is not reflected in the protocol hierarchy.")
    args = ap.parse_args()

    # Preflight checks. An empty inventory produced from a missing or
    # unreadable file would be indistinguishable from a capture containing no
    # hosts, so these conditions are reported as errors instead.
    if not os.path.isfile(args.pcap):
        sys.exit(f"ERROR: '{args.pcap}' does not exist.")
    if os.path.getsize(args.pcap) == 0:
        sys.exit(f"ERROR: '{args.pcap}' is empty (0 bytes).")
    try:
        probe = subprocess.run(["tshark", "-r", args.pcap, "-c", "1"],
                               capture_output=True, text=True, check=False)
    except FileNotFoundError:
        sys.exit("ERROR: tshark not found. Install it with:\n"
                 "  sudo apt install tshark")
    if probe.returncode != 0:
        msg = probe.stderr.strip().splitlines()
        hint = ""
        if any("permission" in m.lower() for m in msg):
            hint = ("\nHINT: AppArmor confines tshark on Ubuntu 24.04. Check:"
                    "\n  sudo dmesg | grep -i apparmor | grep tshark")
        sys.exit(f"ERROR: tshark cannot read '{args.pcap}':\n"
                 + "\n".join(msg[-3:]) + hint)
    if args.score and not os.path.isfile(args.score):
        sys.exit(f"ERROR: ground truth '{args.score}' does not exist.")

    if args.sample_limit:
        globals()["PAYLOAD_SAMPLE_LIMIT"] = args.sample_limit
        globals()["ANNOUNCEMENT_SAMPLE_LIMIT"] = args.sample_limit

    inv = Inventory()
    print(f"extracting from {args.pcap}  (passive - no packets sent)")

    # pass_inventory must run first, as it builds the IP-to-MAC map that the
    # remaining passes rely on. Those passes are independent and individually
    # guarded so that one malformed protocol cannot abort the whole run.
    pass_inventory(args.pcap, inv)

    present = None if args.all_passes else protocol_census(args.pcap)
    skipped = []
    for fn in (pass_tcp_stack, pass_ip_stack, pass_services,
               pass_selfdeclared, pass_infrastructure, pass_clinical,
               pass_industrial, pass_banners, pass_tls):
        need = PASS_REQUIREMENTS.get(fn.__name__)
        if present is not None and need and not (need & present):
            skipped.append(fn.__name__.replace("pass_", ""))
            continue
        try:
            fn(args.pcap, inv)
        except Exception as exc:                      # noqa: BLE001
            print(f"  ! {fn.__name__} failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
    if skipped:
        print(f"  skipped        {', '.join(skipped)} "
              f"(no matching protocols in capture)")
    refine_ambiguous(inv)
    pass_zones(inv)

    write_outputs(inv, args.assets, args.evidence)
    live = sum(1 for e in inv.evidence if e[4] >= 0)
    print(f"\nwrote {args.assets}   ({len(inv.assets)} assets)")
    print(f"wrote {args.evidence} ({live} evidence records)")

    if args.score:
        score(inv, args.score)


if __name__ == "__main__":
    main()
