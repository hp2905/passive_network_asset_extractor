# Passive Network Asset Extractor

Builds a device inventory from a network capture without transmitting a single
packet.

The tool is intended for operational technology, industrial control and
clinical networks, where active scanning is unacceptable. Probing a
programmable logic controller or a bedside medical device risks disturbing a
live process, so the only safe method is to observe the traffic those devices
already produce. Every attribute reported here is derived from packets the
devices sent of their own accord.

Given a capture, it reports for each device: MAC address, IP addresses, VLAN,
vendor, operating system, model, hostname, device type, role, network zone,
software versions, and the physical switch port where that is advertised.

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.8 or later | Standard library only, no packages to install |
| tshark | 3.x or later | Wireshark's command-line dissector; performs all packet parsing |

`requirements.txt` is present for tooling compatibility but installs nothing.

### Installing tshark

**Debian / Ubuntu**

```bash
sudo apt install tshark
```

The installer asks whether non-superusers may capture packets. Answer **yes**,
then add the account to the resulting group and start a new login session:

```bash
sudo usermod -aG wireshark $USER
```

**RHEL / Fedora**

```bash
sudo dnf install wireshark-cli
```

**macOS**

```bash
brew install wireshark
```

**Windows**

Install Wireshark from <https://www.wireshark.org/download.html>. During
installation, leave the TShark component selected; it is included by default
but can be deselected accidentally.

Wireshark does not add itself to `PATH`, so `tshark` will not be found from a
fresh terminal until it is added. Either add the installation directory
permanently through Settings, or set it for the current session:

```powershell
# PowerShell, current session only
$env:Path += ";C:\Program Files\Wireshark"
```

```cmd
:: Command Prompt, current session only
set PATH=%PATH%;C:\Program Files\Wireshark
```

To make it permanent, open Settings, search for "Edit the system environment
variables", choose Environment Variables, select **Path** under user variables,
choose Edit, then New, and add `C:\Program Files\Wireshark`. Open a new
terminal afterwards for the change to take effect.

Reading a saved capture does not require administrator rights on any platform.
Only live capture does, and this tool never captures.

### Verifying the installation

```bash
python3 --version
tshark --version
tshark -r yourcapture.pcap -c 1
```

On Windows, use `python` rather than `python3` unless the Python launcher is
installed, in which case `py` also works:

```powershell
python --version
tshark --version
tshark -r yourcapture.pcap -c 1
```

The third command should print one packet summary. If it fails, see
[Troubleshooting](#troubleshooting).

---

## Usage

```bash
python3 extract.py capture.pcap
```

On Windows, substitute `python` for `python3` throughout this document:

```powershell
python extract.py capture.pcap
```

Accepts `.pcap` and `.pcapng`. Two files are written to the working directory.

Paths containing spaces must be quoted, which is common on Windows:

```powershell
python extract.py "C:\Users\Name\My Captures\site.pcapng"
```

| Output | Contents |
|---|---|
| `assets.csv` | One row per device. Best value and confidence for each attribute. |
| `evidence.csv` | Every individual observation, with its source and confidence tier. The audit trail. |

### Options

```
  --assets PATH          Asset inventory output path (default: assets.csv)
  --evidence PATH        Evidence trail output path (default: evidence.csv)
  --score PATH           Score the result against a known-truth CSV
  --sample-limit N       Row cap for payload and announcement passes
  --all-passes           Run every pass regardless of protocols present
```

### Reading the console output

Each pass reports what it found, which is the quickest way to tell whether a
capture contains the evidence you expected:

```
extracting from capture.pcap  (passive - no packets sent)
  inventory        497501 frames -> 28 MACs
  tcp-handshake    106472 SYN/SYN-ACK, 53236 connections, 19 conversation pairs
  ip-stack             11 IP hosts -> 11 OS inferred
  services       roles derived from observed port direction
  self-declared  bacnet=24, dhcp=4, ipp=16, ldap=80, mdns=456, rtsp=120
  infrastructure cdp=60, lldp=121, stp=1819
  clinical       dicom=96, hl7=3000
  banners        nbns=24, sip=48, snmp=119, ssdp=16, ssh=24
  skipped        industrial, tls (no matching protocols in capture)
  refine                3 ambiguous OS labels narrowed
  zones                 5 VLANs classified
```

A pass reporting `none found` where the protocol is known to be present usually
indicates a dissector version difference. `skipped` is normal and means the
capture contains none of the protocols that pass reads.

---

## How it works

Identification proceeds by accumulating evidence rather than by drawing
conclusions and overwriting them. Each observation is recorded with its source
and a confidence tier. Where two sources disagree, both are kept, the higher
tier is reported, and the disagreement is flagged.

That disagreement is often the interesting result. A device whose registered
vendor conflicts with the vendor it declares about itself is either
misidentified or spoofed, and both are worth investigating.

### Confidence tiers

| Tier | Basis | Examples |
|---|---|---|
| T1 · 0.95 | The device stated it | BACnet I-Am, IPP printer model, LLDP description, SNMP sysDescr, DHCP hostname, LDAP bind DN, SSH banner |
| T2 · 0.75 | A registry or fingerprint implies it | OUI vendor, DHCP option 55, raw stack signature, TLS SNI, mDNS service type |
| T3 · 0.50 | Inferred from behaviour | TCP stack signature, service direction, timing regularity |
| T4 · 0.30 | A weak hint | IP-header-only OS, stack family fallback, VLAN co-location |

Higher tiers win absolutely: a single T1 record outranks any number of T4
records. Where several independent sources agree on the same value, confidence
rises slightly, capped below certainty.

The tier values are ordinal ranks expressed as decimals rather than measured
probabilities. Note also that T1 assumes devices report themselves honestly. On
a network where an adversary may be present, self-declared evidence becomes the
least trustworthy category rather than the most.

### Protocols read

Link layer and discovery: ARP, LLDP, CDP, STP, VRRP, mDNS and DNS-SD, NetBIOS,
SSDP and UPnP, DHCP.

Transport and stack fingerprinting: TCP handshake characteristics (initial TTL,
window size, window scale, timestamps, selective acknowledgement) and IP header
characteristics (TTL, don't-fragment flag, IP identification behaviour) for
hosts that never open a TCP connection.

Application: HTTP, TLS certificates and SNI, SSH, FTP, SMTP, SIP, SNMP, LDAP,
SMB2, IPP, RTSP.

Clinical: DICOM application entity titles, HL7 v2 MSH identifiers.

Industrial: BACnet, Modbus, EtherNet/IP and CIP identity, S7comm, DNP3,
IEC 60870-5-104, OPC UA.

---

## Interpreting the results

### Devices without an operating system

A device that transmits only ARP frames yields a vendor and a VLAN but never an
operating system. ARP carries no IP header, so there is no TTL, no fragment
flag and no TCP options to read. This is a property of passive analysis rather
than a defect: presence is detectable from a single frame, but identity
requires the device to say something.

### Capture duration matters

Only devices that transmit during the capture window are discovered at all. A
device that speaks once an hour will be missed by a fifteen-minute capture.
Report the capture duration alongside any inventory, and prefer longer windows
where the environment allows.

### Vendor names may look wrong

MAC address prefixes are registered to legal entities, and those registrations
often predate acquisitions and rebrands. Hardware sold today under one brand
may carry a prefix registered to a company acquired years ago. Where a device
also declares its own vendor, that self-declaration is reported in preference
to the registry name.

### Ambiguity is reported, not hidden

Some signatures cannot be resolved from the available evidence. An initial TTL
of 255 is the default for industrial stacks and for Solaris and AIX alike.
Where nothing corroborates one reading over the other, the tool reports the
ambiguity rather than guessing.

### Known limitations

- The signature tables cover a limited set of stacks. An unlisted signature
  receives a family-level label instead of an exact one. The raw signature is
  recorded in every case, so an unmatched host remains a resolvable lead.
- Identity is keyed on MAC address. Hosts behind network address translation
  collapse into a single entry, and routers appear to own every address behind
  them.
- Vendor resolution depends on the manufacturer database shipped with
  Wireshark. An outdated installation degrades vendor attribution silently.

---

## Scoring against known truth

Where the true inventory of a capture is known, `--score` measures how much of
it was recovered:

```bash
python3 extract.py capture.pcap --score ground_truth.csv
```

```
SCORE vs ground truth
  discovered    28/28  100.0%
  vendor        28/28  100.0%
  os            27/28   96.4%
  zone          28/28  100.0%
  vlan          28/28  100.0%
```

The truth file is a CSV requiring these columns:

| Column | Contents |
|---|---|
| `mac` | MAC address, any case, colon-separated |
| `name` | Label for the device, used in mismatch reports |
| `vendor` | Expected manufacturer |
| `os` | Expected operating system |
| `zone` | Expected network zone: `it`, `ot`, `clinical`, `iot` |
| `vlan` | Expected VLAN identifier |

Additional columns are ignored. Scoring is optional instrumentation and has no
effect on the extraction itself.

---

## Troubleshooting

**`ERROR: tshark not found`** (Windows)

Wireshark does not add itself to `PATH`. Confirm the executable exists, then
add its directory as described under [Installing tshark](#installing-tshark):

```powershell
Test-Path "C:\Program Files\Wireshark\tshark.exe"
```

A 64-bit installation on a system that previously held a 32-bit one may place
it under `C:\Program Files (x86)\Wireshark` instead.

**`python` is not recognised** (Windows)

The Microsoft Store stub intercepts the command when Python was installed
without the `Add python.exe to PATH` option. Either reinstall Python with that
option selected, or use the launcher, which is registered separately:

```powershell
py --version
py extract.py capture.pcap
```

**`tshark: You don't have permission to read the file`, but the file is
readable** (Linux)

The file permissions are not the problem. On distributions using AppArmor,
tshark runs under a confinement profile that restricts which paths it may open,
independently of ordinary Unix permissions. Confirm with:

```bash
sudo dmesg | grep -i apparmor | grep tshark
```

A `DENIED` line naming the capture confirms it. Either move the capture to a
permitted location such as `/tmp`, or grant read access to the directory:

```bash
sudo tee /etc/apparmor.d/local/tshark << 'EOF'
owner /path/to/captures/** r,
EOF
sudo apparmor_parser -r /etc/apparmor.d/tshark
```

**A pass reports `none found` for a protocol that is present**

Field names differ between tshark versions. Confirm the dissector exposes the
expected field:

```bash
tshark -r capture.pcap -Y protocol -T fields -e protocol.fieldname
```

**A result looks wrong**

Query the evidence trail for the device in question:

```bash
grep "00:1b:0d:aa:bb:01" evidence.csv
```

```powershell
Select-String "00:1b:0d:aa:bb:01" evidence.csv
```

Every observation is listed with its source and tier, showing which evidence
was selected and what it displaced.
