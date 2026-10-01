# extract.py Developer Guide

A reference for reading, maintaining and extending `extract.py`. It is written to be read alongside the source file.

## How to use this guide

Sections 4 to 29 follow the source file from top to bottom. Every heading names the symbols it describes and their line range in the current version. Symbol names are stable; line numbers drift as the file is edited, so search by name when the two disagree.

[Section 30](#30-why-each-value-is-what-it-is) justifies every fixed number, table entry and threshold in the file: where it comes from, whether an external source supports it, what changing it does, and a verdict. Each walkthrough section ends with links to the entries for the values it uses, so a reader who wonders why a value is what it is can find the answer from the place where it appears.

To go from a value in the output back to the code that produced it, take the `source` column of `evidence.csv` and look it up in [Appendix A](#appendix-a-evidence-source-index). Every label the code can emit is listed there with the function that writes it.

Section 2 describes the order in which things execute, which differs from the order in which they appear in the file. Remaining limitations and open questions are collected in [section 31](#31-open-issues-and-limitations).

---

## 1. Overview

The program reads a packet capture and writes a device inventory without transmitting anything. It depends on one external program, `tshark`, which performs all protocol dissection. Python code never parses packets directly; it asks tshark for specific fields, or for the protocol tree of specific packets, and interprets what comes back.

The central design decision is that the program stores evidence rather than conclusions. Each observation is recorded as a row stating which device it concerns, which attribute, what value, which source produced it and at what confidence tier. Conclusions are drawn only at output time, by ranking the rows for each attribute. Contradictory observations are therefore never lost; they are ranked, and the disagreement is reported.

A second principle governs the operating system labels: a label is only as specific as its evidence. A version is reported only where a published signature or a documented rule supports it. Otherwise the program reports the family, at the lowest tier.

---

## 2. Execution flow

`main()` performs these steps in order:

1. Parse command-line arguments.
2. Run preflight checks on the capture file and on tshark.
3. Apply `--sample-limit` to `PER_SOURCE_SAMPLE_LIMIT`, if given.
4. Create an empty `Inventory`.
5. Run `pass_inventory`, unconditionally.
6. Run `protocol_census`, unless `--all-passes` is set.
7. Run each evidence pass in this fixed order, skipping any whose protocols the census did not find: `pass_tcp_stack`, `pass_ip_stack`, `pass_services`, `pass_selfdeclared`, `pass_infrastructure`, `pass_clinical`, `pass_industrial`, `pass_banners`, `pass_tls`.
8. Run `refine_ambiguous`.
9. Run `pass_zones`.
10. Write `assets.csv` and `evidence.csv`.
11. Run `score`, if `--score` was given.

### Ordering constraints

Four dependencies are real, and reordering across them breaks results without raising an error.

| Constraint | Reason |
|---|---|
| `pass_inventory` runs before everything else | It alone populates `inv.ip2mac`. Every other pass records evidence through `add_by_ip()`, which silently discards the record when the IP is unknown. |
| `pass_services` runs after `pass_tcp_stack` | `pass_tcp_stack` fills the `serves` and `consumes` sets for TCP. `pass_services` adds the UDP entries and then converts both sets into `service` and `role` evidence. Run it first and every TCP service is lost. |
| `refine_ambiguous` runs after all evidence passes | It reads `os`, `stack_raw` and `device_type` evidence written by several passes. |
| `pass_zones` runs last among the analysis steps | It reads `service` evidence, which is written by `pass_services`, `pass_industrial` and `_harvest_service_types`. |

The remaining evidence passes are independent of one another. Each is wrapped in its own `try/except` in `main()`, so an exception in one prints a warning and the run continues.

### Cost model

Every call to tshark reads and dissects the entire capture, regardless of the display filter applied. Filter selectivity barely changes the cost; the number of reads determines runtime. A run that executes every pass performs the following reads:

| Stage | Reads |
|---|---|
| Preflight probe | 1, but stops after one frame |
| `pass_inventory`, `protocol_census` | 1 each |
| `pass_tcp_stack`, `pass_ip_stack`, `pass_services`, `pass_infrastructure` | 1 each |
| `pass_selfdeclared` | 3: the combined read, the RTSP payload read, and the verbose BACnet read in `_bacnet_vendor_names` |
| `pass_clinical`, `pass_industrial`, `pass_tls` | 2 each |
| `pass_banners` | 2: the combined field read and the SNMP tree read in `_harvest_snmp` |

That is seventeen full reads. Passes skipped by the census save theirs. On a capture of roughly 500,000 packets one read takes around fourteen seconds, so adding a pass adds its read cost to every run, whether or not the capture contains the protocol. The per-source sample limit does not end a read early; it only limits how many rows from each source are processed.

---

## 3. Symbol map

In file order.

| Lines | Kind | Symbol | Section |
|---|---|---|---|
| 1-52 | docstring, imports | | [4](#4-module-header-and-imports-lines-1-52) |
| 54 | constant | `T1, T2, T3, T4, T5` | [5](#5-confidence-tiers-lines-54-56) |
| 55-56 | constant | `TIER_NAME` | [5](#5-confidence-tiers-lines-54-56) |
| 82-126 | constant | `P0F_SYN` | [6.1](#61-p0f_syn-and-p0f_synack-lines-82-216) |
| 127-216 | constant | `P0F_SYNACK` | [6.1](#61-p0f_syn-and-p0f_synack-lines-82-216) |
| 218 | constant | `LINUX_SYN_LAYOUT` | [6.2](#62-linux_syn_layout-windows_syn_layout-and-ttl_bases-lines-218-224) |
| 219 | constant | `WINDOWS_SYN_LAYOUT` | [6.2](#62-linux_syn_layout-windows_syn_layout-and-ttl_bases-lines-218-224) |
| 224 | constant | `TTL_BASES` | [6.2](#62-linux_syn_layout-windows_syn_layout-and-ttl_bases-lines-218-224) |
| 230 | constant | `AMBIGUOUS_TTL255` | [7](#7-tuning-constants-lines-230-248) |
| 235 | constant | `EPHEMERAL_PORT_FLOOR` | [7](#7-tuning-constants-lines-230-248) |
| 241 | constant | `PER_SOURCE_SAMPLE_LIMIT` | [7](#7-tuning-constants-lines-230-248) |
| 247 | constant | `IPID_MAX_STEP` | [7](#7-tuning-constants-lines-230-248) |
| 248 | constant | `IPID_INCREASING_SHARE` | [7](#7-tuning-constants-lines-230-248) |
| 251-309 | constant | `PORT_ROLES` | [8.1](#81-port_roles-lines-251-309) |
| 314 | constant | `UDP_PEER_PORTS` | [8.2](#82-udp_peer_ports-line-314) |
| 317-324 | constant | `ZONE_HINTS` | [8.3](#83-zone_hints-lines-317-324) |
| 331-357 | constant | `MDNS_SERVICE_TYPES` | [9.1](#91-mdns_service_types-lines-331-357) |
| 362-401 | constant | `BANNER_DEVICE_HINTS` | [9.2](#92-banner_device_hints-lines-362-401) |
| 407-433 | constant | `BANNER_OS_HINTS` | [9.3](#93-banner_os_hints-lines-407-433) |
| 438-445 | constant | `EMBEDDED_DEVICE_CLASSES` | [9.4](#94-embedded_device_classes-lines-438-445) |
| 450-462 | constant | `SSH_OS_HINTS` | [9.5](#95-ssh_os_hints-lines-450-462) |
| 467-470 | function | `first` | [10.1](#101-first-tshark_missing-and-_finish-lines-467-508) |
| 473-475 | constant | `TSHARK_MISSING` | [10.1](#101-first-tshark_missing-and-_finish-lines-467-508) |
| 478-508 | function | `_finish` | [10.1](#101-first-tshark_missing-and-_finish-lines-467-508) |
| 511-544 | function | `tsh` | [10.2](#102-tsh-lines-511-544) |
| 547-556 | function | `_keep_duplicates` | [10.3](#103-tsh_json-and-the-tree-helpers-lines-547-618) |
| 559-592 | function | `tsh_json` | [10.3](#103-tsh_json-and-the-tree-helpers-lines-547-618) |
| 595-605 | function | `_jvalues` | [10.3](#103-tsh_json-and-the-tree-helpers-lines-547-618) |
| 608-618 | function | `_jdicts` | [10.3](#103-tsh_json-and-the-tree-helpers-lines-547-618) |
| 621-637 | class | `SourceCap` | [10.4](#104-sourcecap-lines-621-637) |
| 640-720 | class | `Inventory` | [11](#11-inventory-lines-640-720) |
| 727-767 | function | `pass_inventory` | [12](#12-pass_inventory-lines-727-767) |
| 770 | constant | `OPTION_NAMES` | [13](#13-option-parsing-and-signature-lookup-lines-770-862) |
| 773-810 | function | `_parse_tcp_options` | [13](#13-option-parsing-and-signature-lookup-lines-770-862) |
| 813-818 | function | `_initial_ttl` | [13](#13-option-parsing-and-signature-lookup-lines-770-862) |
| 821-839 | function | `_lookup_stack` | [13](#13-option-parsing-and-signature-lookup-lines-770-862) |
| 842-862 | function | `_stack_rule` | [13](#13-option-parsing-and-signature-lookup-lines-770-862) |
| 865-971 | function | `pass_tcp_stack` | [14](#14-pass_tcp_stack-and-_record_timing-lines-865-1001) |
| 974-1001 | function | `_record_timing` | [14](#14-pass_tcp_stack-and-_record_timing-lines-865-1001) |
| 1004-1071 | function | `pass_ip_stack` | [15](#15-pass_ip_stack-lines-1004-1071) |
| 1074-1110 | function | `pass_services` | [16](#16-pass_services-lines-1074-1110) |
| 1113-1121 | function | `_mentions` | [17](#17-_mentions-_banner_os-and-_banner_device_type-lines-1113-1139) |
| 1124-1130 | function | `_banner_os` | [17](#17-_mentions-_banner_os-and-_banner_device_type-lines-1113-1139) |
| 1133-1139 | function | `_banner_device_type` | [17](#17-_mentions-_banner_os-and-_banner_device_type-lines-1113-1139) |
| 1142-1225 | function | `pass_infrastructure` | [18](#18-pass_infrastructure-lines-1142-1225) |
| 1228-1308 | function | `pass_clinical` | [19](#19-pass_clinical-lines-1228-1308) |
| 1311-1358 | function | `pass_industrial` | [20](#20-pass_industrial-lines-1311-1358) |
| 1361-1363 | constant | `TEXT_TYPES` | [21](#21-pass_tls-and-_rdn_text-lines-1361-1424) |
| 1364 | constant | `OID_COMMON_NAME` | [21](#21-pass_tls-and-_rdn_text-lines-1361-1424) |
| 1367-1375 | function | `_rdn_text` | [21](#21-pass_tls-and-_rdn_text-lines-1361-1424) |
| 1378-1424 | function | `pass_tls` | [21](#21-pass_tls-and-_rdn_text-lines-1361-1424) |
| 1427-1446 | function | `_bacnet_vendor_names` | [22](#22-_bacnet_vendor_names-lines-1427-1446) |
| 1449-1561 | function | `pass_selfdeclared` | [23](#23-pass_selfdeclared-and-_harvest_service_types-lines-1449-1583) |
| 1564-1583 | function | `_harvest_service_types` | [23](#23-pass_selfdeclared-and-_harvest_service_types-lines-1449-1583) |
| 1586-1670 | function | `pass_banners` | [24](#24-pass_banners-and-_harvest_snmp-lines-1586-1718) |
| 1673 | constant | `SNMP_SYSDESCR` | [24](#24-pass_banners-and-_harvest_snmp-lines-1586-1718) |
| 1674 | constant | `SNMP_SYSNAME` | [24](#24-pass_banners-and-_harvest_snmp-lines-1586-1718) |
| 1675 | constant | `SNMP_SYSLOCATION` | [24](#24-pass_banners-and-_harvest_snmp-lines-1586-1718) |
| 1678-1718 | function | `_harvest_snmp` | [24](#24-pass_banners-and-_harvest_snmp-lines-1586-1718) |
| 1721-1743 | function | `protocol_census` | [25](#25-protocol_census-and-pass_requirements-lines-1721-1756) |
| 1748-1756 | constant | `PASS_REQUIREMENTS` | [25](#25-protocol_census-and-pass_requirements-lines-1721-1756) |
| 1759 | constant | `TTL255_GENERAL` | [26](#26-refine_ambiguous-lines-1759-1810) |
| 1760 | constant | `TTL255_MINIMAL` | [26](#26-refine_ambiguous-lines-1759-1810) |
| 1761 | constant | `TTL255_DECLARED` | [26](#26-refine_ambiguous-lines-1759-1810) |
| 1764-1810 | function | `refine_ambiguous` | [26](#26-refine_ambiguous-lines-1759-1810) |
| 1813-1835 | function | `pass_zones` | [27](#27-pass_zones-lines-1813-1835) |
| 1839-1843 | constant | `ATTRS` | [28](#28-attrs-and-write_outputs-lines-1839-1876) |
| 1846-1876 | function | `write_outputs` | [28](#28-attrs-and-write_outputs-lines-1839-1876) |
| 1882-1883 | function | `norm` | [29](#29-scoring-lines-1882-1989) |
| 1890-1898 | constant | `VENDOR_ALIASES` | [29](#29-scoring-lines-1882-1989) |
| 1902-1908 | function | `vendor_ok` | [29](#29-scoring-lines-1882-1989) |
| 1915-1925 | constant | `OS_FAMILIES` | [29](#29-scoring-lines-1882-1989) |
| 1928-1931 | function | `_os_families` | [29](#29-scoring-lines-1882-1989) |
| 1934-1939 | function | `os_ok` | [29](#29-scoring-lines-1882-1989) |
| 1942-1989 | function | `score` | [29](#29-scoring-lines-1882-1989) |
| 1993-2074 | function | `main` | [2](#2-execution-flow) |

---

## 4. Module header and imports (lines 1-52)

The module docstring doubles as the `--help` text: `main()` passes `__doc__` to `argparse` with `RawDescriptionHelpFormatter`, which preserves its line breaks. Edits to the docstring therefore change what users see.

All imports are standard library. `subprocess` runs tshark; `json` parses the protocol trees returned by `tsh_json`; `binascii` decodes the hexadecimal payloads tshark returns; `statistics` supplies the mean and population standard deviation for timing analysis; `csv` reads the truth file and writes both outputs.

---

## 5. Confidence tiers (lines 54-56)

```python
T1, T2, T3, T4, T5 = 0.95, 0.75, 0.50, 0.30, 0.20
```

The tier is the fifth argument to every `add()` call and is chosen by the author of that call; nothing computes it. The convention used throughout:

| Tier | Name | Assign it when |
|---|---|---|
| T1 | self-declared | The device itself stated the value in a protocol field meant for that purpose. |
| T2 | semi-explicit | A registry or fingerprint implies the value, or the value is derived from a T1 statement by a mapping. |
| T3 | inferred | The value is inferred from behaviour, or from a specific published multi-feature signature. |
| T4 | weak | The value rests on a generic signature, a rule supported by secondary sources, or weak behavioural evidence. |
| T5 | family | The value is an operating system family derived from the initial TTL, with at most the presence of TCP options. |

The second T2 case matters in practice. An SSH banner stating `Ubuntu` is recorded as T1 `software`, while the operating system inferred from it is recorded as T2 `os`, because the mapping from banner text to operating system is the code's inference, not the device's statement.

T5 exists so that a family label can never outrank a more specific label. Both kinds of evidence are recorded for most hosts, often in unequal numbers, and `resolve()` breaks ties within a tier by observation count. Without a separate tier, a family label backed by many packets would outvote a signature match backed by fewer.

`TIER_NAME` fills the `tier_name` column of `evidence.csv`.

**Why these values:** [V1](#v1-confidence-tier-values).

---

## 6. Fingerprint signature tables

### 6.1 P0F_SYN and P0F_SYNACK (lines 82-216)

Map a TCP handshake signature to an operating system label. `P0F_SYN` is consulted for SYN packets, which fingerprint clients, and `P0F_SYNACK` for SYN-ACK packets, which fingerprint servers. Both were generated from the p0f 3.09b database rather than typed by hand.

**Key:** `(initial_ttl, window, window_scale, option_layout)`.

| Position | Type | Meaning |
|---|---|---|
| 0 | int | Initial TTL: 32, 64, 128 or 255 |
| 1 | int or str | An absolute window, or `"mss*N"` meaning N times the MSS advertised in the same packet |
| 2 | int or `"*"` | Window scale shift. An absent option is recorded as 0, as p0f does. `"*"` marks p0f's generic signatures, which accept any scale |
| 3 | str | Option kinds in wire order, using p0f's names: `mss`, `nop`, `ws`, `sok`, `sack`, `ts`, `eol+N` |

**Value:** `(label, generic)`. The label is p0f's own. `generic` is true for p0f's generic signatures, which are filed at T4; specific ones are filed at T3.

Keying on the MSS multiple rather than only the absolute window matters because many stacks size their window as a multiple of the MSS, which varies with the link. The option layout matters because it distinguishes stacks whose numeric values coincide.

**Why these values:** [V3](#v3-p0f-signature-tables), [V4](#v4-signature-matching-order).

### 6.2 LINUX_SYN_LAYOUT, WINDOWS_SYN_LAYOUT and TTL_BASES (lines 218-224)

The two layout strings are the SYN option orders of Linux and Windows, used by `_stack_rule()`. `TTL_BASES` lists the initial TTL values that `_initial_ttl()` rounds to.

**Why these values:** [V5](#v5-rules-for-current-systems), [V6](#v6-initial-ttl-bases).

---

## 7. Tuning constants (lines 230-248)

| Constant | Value | Used by | Effect |
|---|---|---|---|
| `AMBIGUOUS_TTL255` | string | stack passes, `refine_ambiguous` | The label for a TTL-255 host whose stack is not otherwise identified. `refine_ambiguous` finds such hosts by comparing against this exact string. |
| `EPHEMERAL_PORT_FLOOR` | 32768 | `pass_tcp_stack` | A SYN to a port at or above this value, and absent from `PORT_ROLES`, is not recorded as a service. |
| `PER_SOURCE_SAMPLE_LIMIT` | 100 | `SourceCap` | Maximum rows processed per source in passes that read payloads or repeated announcements. |
| `IPID_MAX_STEP` | 4096 | `pass_ip_stack` | Largest step between consecutive IP IDs counted as an increase. |
| `IPID_INCREASING_SHARE` | 0.75 | `pass_ip_stack` | Share of steps that must be increases for the sequence to be recorded as increasing. |

`PER_SOURCE_SAMPLE_LIMIT` is read when each `SourceCap` is created, which is why `main()` can override it with `globals()[...] = ...` after the functions are defined.

**Why these values:** [V7](#v7-ambiguous_ttl255-label), [V8](#v8-ephemeral_port_floor), [V9](#v9-per_source_sample_limit), [V10](#v10-ip-id-classification-values).

---

## 8. Port, service and zone tables

### 8.1 PORT_ROLES (lines 251-309)

**Key:** port number. **Value:** `(service, role_if_serving, role_if_consuming)`.

Consumed by `pass_tcp_stack` and `pass_services`, which turn observed port direction into `service` and `role` evidence, and indirectly by `pass_zones()` through the service names. A port absent from this table produces no service evidence even when traffic on it is observed, though it still appears in the `serves_ports` and `consumes_ports` columns of `assets.csv`. Presence in this table also exempts a port from `EPHEMERAL_PORT_FLOOR`.

**Why these values:** [V11](#v11-port_roles-entries).

### 8.2 UDP_PEER_PORTS (line 314)

Ports on which both ends of an exchange conventionally use the same port number. In `pass_services()`, a datagram whose source and destination ports are equal and in this set marks the sender as serving that port, since neither party is a client in the usual sense.

**Why these values:** [V12](#v12-udp_peer_ports-entries).

### 8.3 ZONE_HINTS (lines 317-324)

**Key:** zone name. **Value:** set of service names drawn from the first element of `PORT_ROLES` values.

Dictionary order is significant. `pass_zones()` breaks ties in favour of the zone listed first, so the order `ot`, `clinical`, `it`, `iot` is a priority order.

**Why these values:** [V13](#v13-zone_hints-membership-and-order).

---

## 9. Text-matching tables

### 9.1 MDNS_SERVICE_TYPES (lines 331-357)

**Key:** a DNS-SD service type label such as `_ipp`, without the protocol suffix. **Value:** `(device_type, service_description)`. A device type of `None` means the service is too generic to indicate a device class, and only the service is recorded.

Used by `_harvest_service_types()`. Evidence from it is T2, because offering a service indicates function without the device stating what it is.

**Why these values:** [V14](#v14-mdns_service_types-entries).

### 9.2 BANNER_DEVICE_HINTS (lines 362-401)

An ordered list of `(term, device_type)` pairs. `_banner_device_type()` lowercases its input and returns the device type of the first term found at the start of a word. Order is priority: `laserjet` must precede `printer`, and specific medical terms precede generic ones such as `controller`.

**Why these values:** [V15](#v15-banner_device_hints-entries).

### 9.3 BANNER_OS_HINTS (lines 407-433)

Same structure and matching as the previous table, returning an operating system name. Used by `_banner_os()`.

**Why these values:** [V16](#v16-banner_os_hints-entries).

### 9.4 EMBEDDED_DEVICE_CLASSES (lines 438-445)

A set of device type strings that identify purpose-built hardware. Used only by `refine_ambiguous()`: a TTL-255 host that has declared one of these types, and has no usable TCP signature, is resolved to an embedded stack. The strings must match the device type values emitted elsewhere exactly, so adding a device type to `BANNER_DEVICE_HINTS` without adding it here means that type never resolves an ambiguous host.

**Why these values:** [V17](#v17-embedded_device_classes-entries).

### 9.5 SSH_OS_HINTS (lines 450-462)

Same structure as the banner tables, applied only to SSH protocol banners by `pass_banners()`, with the same word-start matching. Separate from `BANNER_OS_HINTS` because SSH banners name distributions and products in stable forms, for example `Ubuntu-3ubuntu13` or `ROSSSH`.

**Why these values:** [V18](#v18-ssh_os_hints-entries).

---

## 10. tshark interface

### 10.1 first, TSHARK_MISSING and _finish (lines 467-508)

```python
def first(val):
    return val.split(",")[0] if val else ""
```

When a field occurs more than once in a frame, tshark joins the occurrences with commas. `first()` keeps the first. It must not be applied to fields whose values contain commas as part of their normal syntax; the code deliberately skips it for LDAP distinguished names, HTTP User-Agent strings, and comma-joined lists that are later split and paired, such as IPP attribute names and values.

`TSHARK_MISSING` is the message printed when tshark cannot be started. It is platform-neutral and points to the README, since installation differs between operating systems.

`_finish(proc)` stops and reaps a tshark process. It closes the output pipe first, which makes tshark exit through SIGPIPE on its next write, and only then attempts `terminate()` and later `kill()`, ignoring permission errors. Signals are a fallback because a confined tshark may be refused signals from the Python process, and an unhandled refusal would abort the pass. It returns tshark's standard error.

**Why these values:** [V19](#v19-field-separators), [V20](#v20-process-timeouts-and-message-length).

### 10.2 tsh (lines 511-544)

```python
def tsh(pcap, fields, dfilter=None, limit=None)
```

Runs one tshark field extraction and yields one list of strings per matching frame.

**Command constructed:**

```
tshark -r <pcap> -T fields -E separator=\t [-Y <dfilter>] -e <field1> -e <field2> ...
```

Rows are read from tshark's output as they arrive, split on tabs, and padded or truncated to exactly `len(fields)` elements, so callers can always unpack a fixed number of values even when trailing fields are empty. If `limit` is given, reading stops after that many rows; no current pass uses it, since sampling is done per source by `SourceCap`. On exit, `_finish()` stops tshark, and if the pass produced no rows and tshark reported an error, the first 300 characters are printed as a warning.

Because it is a generator, cleanup runs when the caller's loop ends, including when the caller breaks out early or raises.

**Why these values:** [V19](#v19-field-separators), [V20](#v20-process-timeouts-and-message-length).

### 10.3 tsh_json and the tree helpers (lines 547-618)

Field output lists each field independently, so values that belong together lose their grouping. An SNMP response lists all object names in one list and all octet-string values in another, and the two cannot be paired reliably once other value types are present. A certificate lists its issuer's name components and its subject's in the same list. `tsh_json(pcap, dfilter)` instead asks tshark for the protocol tree in JSON, which keeps each binding and each name component in its own object.

It yields one parsed packet at a time. tshark writes its JSON as an array whose packet objects start with a line `  {` and end with `  }` or `  },`, at two-space indent. The function collects the lines between and parses each packet separately, so memory stays bounded on large captures.

`_keep_duplicates` is the parser's object hook. tshark emits repeated subtrees under the same key within one object; Python's default parser would keep only the last, silently dropping data, so every value is kept as a list instead.

`_jvalues(node, key)` yields every value stored under `key` anywhere in a tree, in document order. `_jdicts(node, key)` yields every object that directly contains `key`, which is how a binding or name component is kept together with its siblings.

### 10.4 SourceCap (lines 621-637)

Admits at most `PER_SOURCE_SAMPLE_LIMIT` rows for each key. Passes create one per read and call `take(key)` for each row, skipping the row when it returns false. The key is the sending host, the host pair where a value is attributed to both ends, or the device and protocol where one device sends several protocols at very different rates.

**Why these values:** [V9](#v9-per_source_sample_limit).

---

## 11. Inventory (lines 640-720)

Holds all state for a run. One instance is created in `main()` and passed to every pass.

### Attributes

**`assets`**: a `defaultdict` keyed by lowercase MAC address. Accessing an unknown MAC creates its entry. Each entry holds:

| Key | Type | Filled by | Meaning |
|---|---|---|---|
| `ips` | set of str | `pass_inventory` | Every source IP seen from this MAC, excluding `0.0.0.0` |
| `vlans` | set of str | `pass_inventory` | Every VLAN ID seen on frames from this MAC |
| `first`, `last` | float | `touch()` | Earliest and latest frame timestamps |
| `packets` | int | `pass_inventory` | Frames sent by this MAC |
| `serves` | set of int | `pass_tcp_stack`, `pass_services` | Ports this host answered on |
| `consumes` | set of int | `pass_tcp_stack`, `pass_services` | Ports this host connected to |

**`evidence`**: a list of six-element lists, one per distinct observation.

| Index | Content |
|---|---|
| 0 | MAC address |
| 1 | Attribute name |
| 2 | Value, always converted to `str` |
| 3 | Source label |
| 4 | Tier as a float, or `-1` once retired by `drop()` |
| 5 | Observation count |

Rows are lists rather than tuples so that the count and the tier can be updated in place.

**`_seen`**: maps `(mac, attr, value, source)` to the row's index. Used by `add()` to detect repeats.

**`_index`**: maps `(mac, attr)` to the list of row indices for that pair, so candidates are found without scanning all evidence.

**`ip2mac`**: maps an IP address to a MAC address, built by `pass_inventory()` with `setdefault`, so the first MAC seen using an address keeps it.

### Methods

**`touch(mac, ts=None)`**: returns the asset entry, creating it if needed, and widens its first and last timestamps to include `ts`.

**`add(mac, attr, value, source, tier)`**: records one observation. Does nothing when `mac` is empty or `value` is `None`, an empty string or the literal `unknown`. An integer zero is accepted, which matters for `hops_from_sensor`. A repeat of an identical `(mac, attr, value, source)` increments that row's count instead of adding a row.

**`add_by_ip(ip, attr, value, source, tier)`**: looks up the MAC for `ip` and calls `add()`. If the IP is not in `ip2mac`, the observation is silently dropped. This is the reason `pass_inventory` must run first.

**`drop(mac, attr, value_prefix)`**: retires every row for `(mac, attr)` whose value starts with `value_prefix`, by setting its tier to `-1` and removing it from `_index`. The row stays in `evidence`, but `cands()` and `write_outputs()` exclude it. Only `refine_ambiguous()` calls this.

**`cands(mac, attr)`**: the live rows for `(mac, attr)`.

**`resolve(mac, attr)`**: selects the reported value, returning `(value, confidence, source)`, or `(None, 0.0, "")` when there are no candidates.

1. Sort candidates by tier, then by observation count, both descending.
2. Take the first as the winner.
3. Collect the distinct source labels among candidates whose value equals the winner's.
4. Confidence is the winner's tier plus 0.05 for each source beyond the first, capped at 0.99.

A single T1 row therefore beats any number of lower-tier rows. The agreement bonus counts distinct source labels, not observations, so repetition from one source never raises confidence. `pass_tcp_stack` embeds the handshake direction in its labels, so a host seen as both client and server receives the bonus from two labels describing the same stack.

Worked example, from a building controller:

| Value | Source | Tier | Count |
|---|---|---|---|
| `Telemecaniqu` | `oui-registry` | T2 | 7 |
| `Schneider Electric` | `bacnet-vendor-id` | T1 | 6 |

The T1 row wins despite fewer observations, at confidence 0.95. Both rows remain in `evidence.csv`, and `conflicts()` reports two values.

**`values(mac, attr)`**: the set of distinct live values. **`conflicts(mac, attr)`**: those values sorted, when there is more than one.

**Why these values:** [V2](#v2-agreement-bonus-and-confidence-cap), [V21](#v21-values-ignored-by-add).

---

## 12. pass_inventory (lines 727-767)

The only pass that sees every frame, and the only one that populates `ip2mac`.

**Reads:** every frame, no filter. Fields `frame.time_epoch`, `eth.src`, `eth.src_resolved`, `vlan.id`, `ip.src`.

**Per frame:**

1. Lowercase the source MAC. Skip it if the least significant bit of its first octet is set, which marks a multicast or broadcast address.
2. Update timestamps and increment the packet count.
3. Add the VLAN ID. Add the source IP and map it to this MAC, unless the IP is `0.0.0.0`, the unspecified address a DHCP client uses before it has a lease. That address belongs to no host, and mapping it would pool every DHCP client's evidence onto the first one seen.
4. If tshark resolved the MAC to a manufacturer, which it renders as `Vendor_xx:xx:xx`, record the text before the last underscore as the vendor. A guard rejects values that are themselves hexadecimal byte triples.

**Writes:** `vendor` from `oui-registry` at T2.

Vendor names come from Wireshark's manufacturer database, so an outdated Wireshark installation degrades attribution without any error.

**Why these values:** [V22](#v22-multicast-mac-test), [V23](#v23-oui-guard-pattern).

---

## 13. Option parsing and signature lookup (lines 770-862)

**`_parse_tcp_options(opt_hex)`** decodes the hexadecimal `tcp.options` field into `(mss, wscale, has_timestamps, has_sack, layout)`. It walks the TLV structure: kind 0 ends the list and is recorded as `eol+N` with N the remaining padding bytes, kind 1 is a single `nop` byte, and every other kind is followed by a length byte covering the whole option. `OPTION_NAMES` maps kinds to p0f's names; unknown kinds are recorded as `?N`. Malformed input ends the walk and returns what was found so far.

**`_initial_ttl(ttl)`** rounds an observed TTL up to the nearest value in `TTL_BASES`. The difference is the number of routers crossed, recorded as `hops_from_sensor`.

**`_lookup_stack(table, ittl, win, mss, scale, layout, wildcard=False)`** looks a handshake up in a p0f table. It tries the absolute window and then, when the window divides exactly by the MSS, the window as `mss*N`. With `wildcard=False` only signatures naming the exact scale are considered; with `wildcard=True` only p0f's generic signatures. It returns `(label, tier, kind)` or `None`.

**`_stack_rule(direction, ittl, win, mss, scale, layout)`** covers current systems that the p0f database predates. It applies to SYN packets only and returns `(label, tier)` or `None`:

| Rule | Condition | Label | Tier |
|---|---|---|---|
| Current Linux | TTL 64, Linux option order, window equal to the largest multiple of the MSS that fits in 65535 | `Linux 5.x or later` | T3 |
| Current Windows | TTL 128, Windows option order, window 65535, scale 8 | `Windows 10 or later` | T4 |

**Why these values:** [V3](#v3-p0f-signature-tables), [V4](#v4-signature-matching-order), [V5](#v5-rules-for-current-systems), [V6](#v6-initial-ttl-bases), [V24](#v24-tcp-option-kinds-and-names).

---

## 14. pass_tcp_stack and _record_timing (lines 865-1001)

Derives three things from handshake packets in a single read: stack fingerprints, service direction, and connection timing.

**Reads:** filter `tcp.flags.syn==1`, which matches both SYN and SYN-ACK. Fields `frame.time_epoch`, `ip.src`, `ip.dst`, `ip.ttl`, `tcp.window_size_value`, `tcp.options`, `tcp.flags.ack`, `tcp.dstport`.

**Per packet, stack fingerprinting:**

1. Skip if source, TTL or window is missing or non-numeric.
2. Determine direction. tshark renders boolean flags as `True` and `False`, so the check accepts both `1` and `true`. Misreading the flag would treat every SYN-ACK as a SYN and record each client's ephemeral port as a service it offers.
3. Parse the options and select `P0F_SYNACK` or `P0F_SYN` by direction.
4. Match, most specific first, and record the first that succeeds:

| Step | Match | Source label | Tier |
|---|---|---|---|
| 1 | p0f signature naming this exact scale | `tcp-stack-p0f-exact/...` | T3 |
| 2 | `_stack_rule()` | `tcp-stack-rule/...` | T3 or T4 |
| 3 | p0f generic signature with wildcard scale | `tcp-stack-p0f-generic/...` | T4 |
| 4 | Family fallback, below | `tcp-stack-family/...` | T5 |

| Initial TTL | Condition | Family label |
|---|---|---|
| 255 | any | `AMBIGUOUS_TTL255` |
| 128 | any | `Windows family` |
| 64 | timestamps present and window scale option present | `Linux / BSD / macOS family` |
| 64 | otherwise | `embedded / minimal stack` |
| 32 | any | `legacy / minimal stack (TTL 32)` |

5. Always write the raw signature, `ttl=,win=,ws=,ts=,sack=,mss=,opts=`, at T2, and the hop count at T3.

The fingerprint is attributed to the packet's source, so SYNs fingerprint clients and SYN-ACKs fingerprint servers. A host that only ever answers is still fingerprinted.

**Per packet, service direction, SYNs only:** skip SYN-ACKs and packets without a destination or port. Count the attempt. Skip a destination port at or above `EPHEMERAL_PORT_FLOOR` unless it is in `PORT_ROLES`. Otherwise add the port to the client's `consumes` set and the server's `serves` set, and append the timestamp to the conversation keyed by `(src, dst, dport)`. These sets become evidence in `pass_services()`.

### _record_timing

Classifies each conversation with at least eight connections by the coefficient of variation of the gaps between them, which is the standard deviation divided by the mean.

| Coefficient | Writes |
|---|---|
| below 0.15 | `behaviour` "deterministic poller" at T3, and `role_hint` at T4 |
| above 0.6 | `behaviour` "bursty" at T4 |
| between | nothing |

**Why these values:** [V4](#v4-signature-matching-order), [V5](#v5-rules-for-current-systems), [V7](#v7-ambiguous_ttl255-label), [V8](#v8-ephemeral_port_floor), [V25](#v25-family-fallback-rules), [V26](#v26-timing-thresholds).

---

## 15. pass_ip_stack (lines 1004-1071)

Records the operating system family from the IP header for traffic other than TCP. It exists for hosts that never open a TCP connection, such as BACnet controllers and SNMP agents.

**Reads:** filter `ip && !tcp && ip.src != 0.0.0.0 && !(ip.dst >= 224.0.0.0 && ip.dst <= 239.255.255.255)`. Fields `ip.src`, `ip.ttl`, `ip.flags.df`, `ip.id`.

Multicast is excluded because several discovery protocols set the TTL by rule rather than by operating system: mDNS always uses 255 and SSDP a small value. Traffic from `0.0.0.0` is excluded because it belongs to no host.

**Per host, after collecting every packet:**

1. Take the most common TTL and the most common DF value. The DF check accepts both `1` and `true`.
2. Classify the IP ID sequence:

| Mode | Condition |
|---|---|
| `unknown` | no IDs |
| `zero` | all zero |
| `constant` | all equal and non-zero |
| `insufficient` | fewer than three IDs |
| `increasing` | at least `IPID_INCREASING_SHARE` of the steps, taken modulo 65536, lie between 1 and `IPID_MAX_STEP` |
| `random` | otherwise |

3. Write the raw signature `ttl=,df=,ipid=` at T2 and the hop count at T3.
4. Write the family for the initial TTL at T5: `AMBIGUOUS_TTL255`, `Windows family`, `Linux, BSD, macOS or embedded (TTL 64)`, or the TTL 32 label.

The DF flag and IP ID mode are recorded but not used to name an operating system, because current stacks vary them by version and configuration.

**Why these values:** [V6](#v6-initial-ttl-bases), [V7](#v7-ambiguous_ttl255-label), [V10](#v10-ip-id-classification-values), [V27](#v27-excluded-ipv4-addresses).

---

## 16. pass_services (lines 1074-1110)

Two responsibilities: determining UDP service direction, and converting every `serves` and `consumes` set, TCP and UDP alike, into evidence.

**Reads:** filter `udp`. Fields `ip.src`, `udp.srcport`, `udp.dstport`.

**Per datagram,** first match wins:

| Condition | Effect on sender |
|---|---|
| source port equals destination port and is in `UDP_PEER_PORTS` | serves that port |
| source port is in `PORT_ROLES` and below 1024 | serves that port |
| destination port is in `PORT_ROLES` | consumes that port |

UDP has no handshake, so direction comes from the source port. A DNS server answers from port 53, while a client sends to port 53 from a high port.

**Then, for every asset:** each served port in `PORT_ROLES` writes `service` and the serving `role`, both T3, from `port-N/server`. Each consumed port in `PORT_ROLES` and not also served writes the consuming `role` at T3 from `port-N/client`.

**Why these values:** [V11](#v11-port_roles-entries), [V12](#v12-udp_peer_ports-entries), [V28](#v28-system-port-boundary).

---

## 17. _mentions, _banner_os and _banner_device_type (lines 1113-1139)

`_mentions(text, needle)` is true when `needle` occurs in `text` at the start of a word, that is, not preceded by a letter or digit. Both arguments are lower case. A plain substring test would match inside unrelated words, such as `ups` in "backups" or `phone` in "iPhone"; checking only the start of the word still accepts plurals and suffixes, such as "switches".

`_banner_os` and `_banner_device_type` lowercase their input and return the value of the first entry in `BANNER_OS_HINTS` or `BANNER_DEVICE_HINTS` that `_mentions` finds, or `None`. They are applied to LLDP descriptions, CDP platform and version strings, SNMP sysDescr, SSDP server headers, CIP product names, TLS certificate names and SSH banners.

**Why these values:** [V15](#v15-banner_device_hints-entries), [V16](#v16-banner_os_hints-entries).

---

## 18. pass_infrastructure (lines 1142-1225)

Link-layer discovery protocols, which carry network structure: switch identity, model, software, and the physical port an endpoint is connected to.

**Reads:** filter `lldp || cdp || stp || vrrp`. Twelve fields covering all four protocols; each row is dispatched on which fields are populated. Rows are capped per device and per protocol. A switch sends a BPDU every two seconds but a CDP announcement only every minute, so a cap shared across protocols would be used up by BPDUs before the first CDP frame arrived, losing the model and port it carries.

**LLDP rows:** system name as hostname (T1); system description as software (T1), with device type and operating system derived through the banner functions (T1), and its first word as vendor (T2); port ID and port description (T1).

**CDP rows:** device ID as hostname (T1); platform as model (T1) with a derived device type (T1); software version as software (T1) with a derived operating system (T1) and its first word as vendor (T2); port ID (T1).

**STP rows:** the sender is labelled a network switch at T3. If the root bridge identifier equals the sender's MAC, it is also labelled the root bridge at T2.

**VRRP rows:** the sender's IP is labelled a redundant gateway at T2 and a router at T3.

Many switches send each BPDU from the MAC of the individual port rather than the bridge's base MAC, so on real equipment one switch may appear as several assets, and the root comparison rarely succeeds.

**Why these values:** [V9](#v9-per_source_sample_limit), [V31](#v31-truncation-lengths).

---

## 19. pass_clinical (lines 1228-1308)

**DICOM read:** filter `dicom.pdu.type == 1 || dicom.pdu.type == 2`, capped per host pair and PDU type. Fields include the PDU type, both AE titles, and the implementation UID and version.

Titles are read from association requests (PDU type 1) only. The calling title is attributed to the sender, with device type `imaging modality` at T2; the called title to the destination, with device type `pacs / image archive` at T2. An association accept (PDU type 2) repeats the same two titles in the opposite direction, so reading titles from it would give each host the other's title. The implementation version and UID in either PDU describe its own sender and are recorded against it at T1 and T2.

**HL7 read:** filter `hl7`, capped per host pair because receiving applications are attributed to the destination. The MSH segment has no dissector fields, so the payload is hex-decoded and searched for a line beginning `MSH` after stripping the MLLP start byte. The segment is split on `|`. Because the first pipe is itself field MSH-1, index 2 is MSH-3, the sending application, index 3 is MSH-4, the sending facility, and index 4 is MSH-5, the receiving application. Sending application and facility go to the source and receiving application to the destination, all at T1. Only the first MSH segment in a payload is used.

**Why these values:** [V9](#v9-per_source_sample_limit), [V29](#v29-dicom-and-hl7-framing-values).

---

## 20. pass_industrial (lines 1311-1358)

**CIP read:** filter `cip`, capped per source. Identity response fields: vendor ID, product name, serial number, device type, and major and minor revision. Product name becomes `model` at T1 with a derived device type; the rest are recorded as raw attributes at T1, and the revisions are joined as `firmware`.

**S7comm and IEC 60870-5-104 read:** filter `s7comm || iec60870_asdu`, capped per source. Any frame of either protocol records the corresponding `service` at T3 against its source.

This pass is not exercised by the synthetic capture used during development, so it has been checked only for syntax and field names.

**Why these values:** [V9](#v9-per_source_sample_limit).

---

## 21. pass_tls and _rdn_text (lines 1361-1424)

**Certificate read:** `tsh_json` over `tls.handshake.type == 11`, the Certificate message, capped per source. From each packet it takes the first certificate, which is the server's own; subsequent ones are the chain. From that certificate it takes the subject name, not the issuer, and within the subject the component whose OID is `2.5.4.3`, commonName. `_rdn_text` performs that selection and accepts any of the string types in `TEXT_TYPES`, since certificates encode names in several. The common name is recorded as `cert_subject` at T1 with a derived device type at T2, and the first DNS subject alternative name as `cert_san` at T1.

**ClientHello read:** filter `tls.handshake.type == 1`, capped per source. Server Name Indication is recorded as `tls_sni_requested` at T2 and the JA3 hash as `ja3` at T2. JA3 characterises the TLS library rather than the host, so it is kept as a raw value.

**Why these values:** [V30](#v30-certificate-name-values), [V31](#v31-truncation-lengths).

---

## 22. _bacnet_vendor_names (lines 1427-1446)

BACnet I-Am frames carry a numeric vendor identifier. Wireshark resolves it to a company name from the ASHRAE registry, but the name appears only in verbose output, not in a field.

This function runs `tshark -V` over I-Am frames and scans the text. A line matching `Source Address: a.b.c.d` sets the current IP; a subsequent line matching `Vendor ID: Name (N)` records the name as `vendor` at T1 from `bacnet-vendor-id`. It is called from inside `pass_selfdeclared()`, performs its own full read, and holds all verbose output in memory before parsing it.

---

## 23. pass_selfdeclared and _harvest_service_types (lines 1449-1583)

Protocols in which a device states its own identity.

**Combined read:** filter

```
dhcp || (mdns && dns.flags.response==1) || bacapp.unconfirmed_service==0
|| ipp || (tcp && http.server) || (tcp && http.user_agent)
|| ldap.name || smb2.dialect
```

Fifteen fields, each row dispatched on which are populated.

| Fields populated | Writes |
|---|---|
| DHCP hostname, vendor class, request list | `hostname` T1 by MAC; `vendor_class` T2; `dhcp_fingerprint` T2, the option 55 list with commas replaced by hyphens |
| mDNS response name | `hostname` T1, unless the name is a DNS-SD service type; then `_harvest_service_types` |
| BACnet instance, vendor ID | `bacnet_instance` T1, `device_type` "bacnet controller" T1, `vendor_id_raw` T1 |
| IPP names and values | for `printer-make-and-model`: `model` T1, `device_type` "printer" T1, first word as `vendor` T1 |
| HTTP Server header | `software` T2 |
| HTTP User-Agent | `user_agent` T2 |
| LDAP DN | `hostname` from `CN=` and `domain` from the `DC=` components, both T1 |
| SMB2 dialect | `smb_dialect` T2 |

DHCP evidence is recorded by MAC rather than by IP, because a client requesting an address sends from `0.0.0.0`.

**RTSP read:** filter `rtsp`, capped per source. RTSP has no field for the Server header, so the payload is decoded and searched for `Server:`. A match records `software` and `device_type` "camera / video source", both T1.

**Then** `_bacnet_vendor_names()` runs.

### _harvest_service_types

Splits the mDNS response and PTR names into dot-separated labels and looks up each label beginning with an underscore in `MDNS_SERVICE_TYPES`. A hit writes `service` at T2, and `device_type` at T2 when the table gives one.

**Why these values:** [V14](#v14-mdns_service_types-entries), [V31](#v31-truncation-lengths).

---

## 24. pass_banners and _harvest_snmp (lines 1586-1718)

Text banners and management descriptions.

**Combined read:** filter

```
ssh.protocol || ftp.response.code == 220 || smtp.response.code == 220
|| sip.User-Agent || nbns.name || (udp.port==1900 && http.server)
```

| Fields populated | Writes |
|---|---|
| SSH protocol banner | `software` T1; operating system from `SSH_OS_HINTS` T2; device type from the banner T2 |
| FTP reply 220 | the greeting text as `software` T1 |
| SMTP reply 220 | the greeting text as `software` T1 |
| SIP User-Agent | `software` T1; `device_type` "voip endpoint" T2; text before the first `/` as `model` T1; text before the first `-` or `/` as `vendor` T2, unless it starts with a digit |
| NetBIOS name | `hostname` T1, with the `<NN>` suffix removed |
| HTTP Server header with UDP source port 1900 | SSDP: `software`, derived `device_type`, derived `os`, all T1 |

FTP and SMTP servers identify themselves in the 220 greeting sent when a connection opens, so only that reply is read.

### _harvest_snmp

Reads SNMP through `tsh_json`, capped per source. For each variable binding, the object identifier and value are taken from the same object in the protocol tree, so they cannot be mispaired. String values arrive hex-encoded. The system group is read:

| OID | Object | Writes |
|---|---|---|
| `1.3.6.1.2.1.1.1` | sysDescr | `software` T1, derived `device_type` T1, derived `os` T1, first word as `vendor` T2 |
| `1.3.6.1.2.1.1.5` | sysName | `hostname` T1 |
| `1.3.6.1.2.1.1.6` | sysLocation | `location` T1 |

**Why these values:** [V18](#v18-ssh_os_hints-entries), [V32](#v32-ftp-and-smtp-greeting-code), [V33](#v33-sip-netbios-and-ssdp-parsing-values), [V34](#v34-snmp-object-identifiers).

---

## 25. protocol_census and PASS_REQUIREMENTS (lines 1721-1756)

**`protocol_census(pcap)`** runs `tshark -q -z io,phs`, which prints the protocol hierarchy with a line per protocol. It collects the first word of every line that contains a colon and consists only of lowercase letters, digits, underscores, dots and hyphens, and for dotted names also the part before the first dot. It returns the set, or `None` if tshark cannot be started or nothing was found. `None` disables gating, so every pass runs.

**`PASS_REQUIREMENTS`** maps a pass name to the protocol names it needs. A pass is skipped when its entry exists and shares no name with the census. Passes with no entry always run. Keys are compared against `fn.__name__`, so renaming a pass without updating its key silently disables gating for it.

**Why these values:** [V35](#v35-census-name-pattern).

---

## 26. refine_ambiguous (lines 1759-1810)

Narrows the `AMBIGUOUS_TTL255` label using other evidence. For each asset whose `os` values include it, the first rule that applies wins:

| Evidence | Verdict | Source | Tier |
|---|---|---|---|
| Raw TCP signature has two or more of window scale, timestamps and SACK, and window 16384 or larger | `TTL255_GENERAL` | `ttl255+feature-rich-stack` | T3 |
| Raw TCP signature has none of the three, and window 8192 or smaller | `TTL255_MINIMAL` | `ttl255+minimal-stack` | T3 |
| No verdict yet, and a declared device type is in `EMBEDDED_DEVICE_CLASSES` | `TTL255_DECLARED` | `ttl255+self-declared-device-class` | T4 |
| None of the above | label retained | | |

Stack richness is checked before declared role because it holds regardless of the application protocol a host speaks. Speaking an OT protocol alone is not used, because a general-purpose host can run an OT gateway. A BACnet I-Am counts as a declared device type, because it is the device declaring itself a BACnet device.

When a verdict is reached, `drop()` retires the ambiguous rows and the verdict is added. If a host has several raw signatures, they are joined and searched as one string; the values come from a set, so when the signatures disagree, which window value is used is not defined.

**Why these values:** [V17](#v17-embedded_device_classes-entries), [V36](#v36-refine_ambiguous-thresholds-and-labels).

---

## 27. pass_zones (lines 1813-1835)

Infers a zone for each VLAN from the services seen on it.

1. For every VLAN, take the union of `service` values across all assets on it.
2. For each zone in `ZONE_HINTS`, count how many of that zone's marker services appear.
3. The zone with the highest count wins. The comparison is strictly greater, so a tie goes to the zone listed first.
4. Every asset on the VLAN receives that zone at T3 from `vlan-N-protocol-mix`.

Assets with no VLAN get no zone. An asset on several VLANs receives one zone row per VLAN; they share a tier and a count, so `resolve()` reports whichever was recorded first.

**Why these values:** [V13](#v13-zone_hints-membership-and-order), [V37](#v37-zone-tie-breaking).

---

## 28. ATTRS and write_outputs (lines 1839-1876)

**`ATTRS`** lists the attributes written to `assets.csv`, in column order. An attribute recorded as evidence but absent from this list appears only in `evidence.csv`: currently `device_type_raw`, `dicom_impl_uid`, `role_hint`, `smb_dialect`, `switch_port_desc`, `tls_sni_requested`, `user_agent`, `vendor_class` and `vendor_id_raw`.

### assets.csv

One row per MAC, sorted by packet count, highest first.

| Column | Content |
|---|---|
| `mac` | Lowercase MAC address |
| `ips` | Source IPs, semicolon-separated |
| `vlan` | VLAN IDs, semicolon-separated |
| `packets` | Frames sent |
| `first_seen`, `last_seen` | Unix epoch seconds, rounded |
| `serves_ports`, `consumes_ports` | Port numbers, semicolon-separated |
| one pair per `ATTRS` entry | The resolved value, and its confidence to two decimals |
| `conflicts` | For `os`, `vendor`, `hostname` and `model` only: entries `attr=N` where N distinct values were observed |

### evidence.csv

Every live evidence row, sorted by MAC, then attribute, value and source.

| Column | Content |
|---|---|
| `mac` | Device |
| `attribute` | Attribute name |
| `value` | Observed value |
| `source` | Source label; see [Appendix A](#appendix-a-evidence-source-index) |
| `tier` | Tier as a decimal |
| `tier_name` | `self-declared`, `semi-explicit`, `inferred`, `weak` or `family` |
| `observations` | Times this exact value was seen from this source |

**Why these values:** [V38](#v38-conflict-attributes).

---

## 29. Scoring (lines 1882-1989)

Optional. Compares the inventory against a known-truth CSV with columns `mac`, `name`, `vendor`, `os`, `zone` and `vlan`.

**`norm(s)`** lowercases and removes everything but letters and digits. **`VENDOR_ALIASES`** groups normalised names that refer to one manufacturer, because MAC registrations use legal names that often predate acquisitions. **`vendor_ok`** accepts exact normalised equality, either string being a prefix of the other, or membership of both in one alias group.

**`OS_FAMILIES`** maps family names to identifying terms. **`_os_families(text)`** returns every family whose terms occur in a label, and **`os_ok(found, truth)`** accepts an exact match or any shared family. The operating system score therefore measures family-level agreement, not version-level identification, and a family label listing several possibilities counts as correct when the expected family is among them.

**`score(inv, truth_path)`** counts discovery, then checks vendor, operating system, zone and VLAN for each truth row. The truth value `medical` is accepted for the extractor's `clinical`. It prints a percentage per attribute, any MACs found that are absent from the truth file, and up to fifteen mismatches.

None of these affect the extractor's output.

**Why these values:** [V39](#v39-scoring-families-and-aliases), [V40](#v40-scoring-display-limits).

---

## 30. Why each value is what it is

Every fixed number, table entry and threshold in `extract.py` is listed here in file order, with where it is used, what it is based on, what happens if it is changed, and a verdict. The walkthrough sections link to the relevant entry wherever a value appears.

### How to read the entries

Each entry states a **basis**, which says where the value comes from:

| Basis | Meaning | Guidance |
|---|---|---|
| Specification | Fixed by an RFC, the IANA registry, or a protocol standard. | Do not change; a different value is a bug. |
| Published data | Taken from a maintained external dataset, such as the p0f signature database or the IEEE registry through Wireshark. | Change only by consulting the source again. |
| Measured | Confirmed by a measurement made while this guide was prepared. The measurement is described. | Re-measure before relying on it for other systems. |
| Derived | Follows from a stated argument, with the exact figure a judgement inside that argument. | Tune freely within the argument. |
| Judgement | Chosen without external support. The entry states the trade-off. | Tune freely; validate on real captures. |

Each entry also gives a **verdict**: *Sound*, *Sound with caveat*, or *Weak*.

### Summary

Every value in the file now has one of the first four bases, or is a judgement with a stated trade-off. The TCP signature tables are generated from the p0f database, and where they are extended for systems newer than it, the extension rests on a measurement or on cited secondary sources and is filed at a tier that reflects that. Where no published signature matches a host, the program reports only the family, at the lowest tier, rather than a specific label it cannot support.

The values with the weakest support are the Windows rule in [V5](#v5-rules-for-current-systems), which rests on secondary sources, and the judgement thresholds for timing and stack richness in [V26](#v26-timing-thresholds) and [V36](#v36-refine_ambiguous-thresholds-and-labels), which are reasoned but unvalidated on real traffic. [Section 31](#31-open-issues-and-limitations) lists these with the other remaining limitations.

One point bears on interpreting results. The synthetic capture used during development was produced by a generator whose device profiles include invented stacks, such as a VxWorks controller and a medical RTOS. No published signature matches them, so the extractor now reports those devices at family level. Its operating system score against that capture measures family-level agreement and should not be read as evidence of version-level accuracy.

---

### V1. Confidence tier values

**Value:** T1 0.95, T2 0.75, T3 0.50, T4 0.30, T5 0.20. **Used in:** every `add()` call; `resolve()`. **Basis:** Judgement, with a derived tier boundary. **Verdict:** Sound for their purpose, which is ordering.

Only the order of the values affects which value `resolve()` reports, because candidates are sorted by tier before anything else and the agreement bonus is added after the winner is chosen. The magnitudes are not measured probabilities and nothing calibrates them. They were chosen so that each tier is visibly distinct, no tier reaches 1.0 because nothing observed passively is certain, and T1 sits below 1.0 because self-declared values can be misconfigured or deliberately falsified.

The boundary between T3, T4 and T5 follows the number of independent features behind a claim. A specific p0f signature fixes TTL, window, scale and option order (T3). A generic signature or a rule leaves one of those open or rests on secondary sources (T4). A family label rests on the TTL alone, with at most the presence of options (T5). T5 was separated from T4 after a measured failure: on the synthetic capture, a domain controller's SYN matched the Windows rule, but its SYN-ACKs and UDP traffic produced more family labels at the same tier, and the vaguer label won on count.

To make the values meaningful as probabilities, run the extractor on captures with known inventories, record how often each source label produces a correct value, and set each tier to the observed accuracy.

### V2. Agreement bonus and confidence cap

**Value:** 0.05 per additional agreeing source; cap 0.99. **Used in:** `resolve()`. **Basis:** Derived. **Verdict:** Sound with caveat.

The bonus changes only the reported confidence, never the winner. It is set relative to the gap of 0.20 or more between the upper tiers: a value needs four additional independent sources before its reported confidence reaches the base of the tier above, so corroboration raises confidence without making a lower tier look as strong as a higher one. The cap exists because a T1 value with two agreeing sources would otherwise report 1.00, which states certainty.

The caveat is that the bonus counts distinct source labels, and `pass_tcp_stack` embeds the handshake direction in its labels, so a host seen as both client and server receives the bonus from two labels that describe the same stack.

### V3. p0f signature tables

**Value:** `P0F_SYN` (43 signatures) and `P0F_SYNACK` (88). **Used in:** `pass_tcp_stack`. **Basis:** Published data. **Verdict:** Sound with caveat.

The tables were generated by a script from the p0f 3.09b database file `p0f.fp`, sections `[tcp:request]` and `[tcp:response]`, so no value was typed by hand. p0f is the most widely used published set of passive TCP signatures. Its window values are kept in its own form, `mss*N` where p0f gives one, so that a signature matches regardless of the link's MSS.

Signatures were excluded where they would mislead on a current network: scanners and p0f's own test tools, named web crawlers, loopback-only signatures, games consoles, and platforms unlikely to be present (Linux 2.0 and 2.2, NeXTSTEP, OpenVMS, Tru64). Seven signatures that require a specific IP option length or MSS were omitted because the key does not carry those fields. Two SYN-ACK signatures are shared by FreeBSD and Mac OS X in p0f itself; they carry both names rather than one chosen arbitrarily.

*Tested:* constructed SYNs for Linux 3.11 and later, Windows 7, Mac OS X and FreeBSD 9 each matched the expected p0f label.

Three caveats. p0f also matches on quirks, such as the DF flag and IP ID behaviour, which the key does not include, so a small number of packets could match here that p0f would reject. The database dates from 2016 and has no entries for Windows 10 or later or for Linux after 3.x, which [V5](#v5-rules-for-current-systems) addresses. And p0f's labels are its own, including their version granularity.

To refresh the tables from a newer database, rerun the generation with the same exclusions.

### V4. Signature matching order

**Value:** exact p0f signature, then rule, then generic p0f signature, then family. **Used in:** `pass_tcp_stack`. **Basis:** Derived. **Verdict:** Sound.

Candidates are tried from most to least specific, and the first match is recorded. A p0f signature naming the exact window scale fixes every field of the key. A rule matches an exact scale but rests on less authoritative evidence. A generic p0f signature leaves the scale as a wildcard. The family fallback uses the TTL alone.

The rule is placed before generic signatures because of a measured conflict. A Windows SYN with window 65535 and scale 8 matched p0f's generic "Windows NT kernel 5.x" signature, whose wildcard accepts any scale, before the rule for current Windows was reached. p0f's own specific XP signatures use scales 0 to 2, never 8, so an exact-scale match is the more specific evidence.

### V5. Rules for current systems

**Used in:** `_stack_rule`. **Verdict:** see each rule.

**Current Linux** (T3). **Basis:** Measured, with a consistent secondary report. **Verdict:** Sound with caveat. A Linux 6.18 kernel on an interface with MTU 1400 sent window 65280 with MSS 1360, which is 48 times 1360, the largest multiple of 1360 that fits in the 16-bit window field. Secondary sources report that Linux 5.x sends 64240 at the usual MSS of 1460, which is 44 times 1460, the largest multiple of 1460 that fits. Both observations follow the same formula, which the rule implements, together with Linux's option order. At MSS 1460 with scale 1 or 3, p0f's Android signature also produces 64240 and takes precedence, since exact p0f matches are checked first. The lower bound of 5.x rests on the secondary report; only 6.18 was measured.

**Current Windows** (T4). **Basis:** secondary sources. **Verdict:** Weak. Several secondary sources report that Windows 10 and 11 send a 65535 window with scale 8. p0f contains no signature for them. No source found here supports the 64240 window also seen from Windows hosts, so that value falls to the family label. Server editions built on the same kernel are expected to present the same SYN, but this was not verified. The rule is filed at T4 because its evidence is secondary.

### V6. Initial TTL bases

**Value:** 32, 64, 128, 255. **Used in:** `_initial_ttl`. **Basis:** Published data. **Verdict:** Sound.

These are the default initial TTLs of nearly all IP stacks in published tables: 64 for Linux, the BSDs and macOS, measured as 64 on the Linux kernel used here; 128 for Windows since NT 4.0; 255 for Cisco IOS and Solaris 2.x; 32 for Windows 95 and NT 3.51. Stacks using 60, such as AIX and Irix, and 30, such as HP-UX 9, round into 64 and 32, which places them in the right band at the cost of an error of up to four in the hop estimate. Rounding up assumes fewer routers than the distance to the next base, which holds comfortably on a local capture.

### V7. AMBIGUOUS_TTL255 label

**Value:** `TTL-255 stack (network equipment, legacy Unix or embedded)`. **Used in:** stack passes, `refine_ambiguous`. **Basis:** Published data. **Verdict:** Sound with caveat.

An initial TTL of 255 does not identify an operating system on its own, so the label records the possibilities. Cisco IOS uses 255, confirmed by several independent sources, and network equipment is the most common source of TTL 255 on current networks. Solaris 2.x used 255, but p0f records Solaris 8 and 10 at 64, so only legacy Unix is included. AIX is not named, because it uses 60. No source was found establishing which embedded stacks use 255; VxWorks, often assumed to, documents a BSD 4.4-derived stack, and BSD's default is 64. Embedded is nevertheless kept in the label, because an ambiguity label should not exclude a possibility without evidence against it.

### V8. EPHEMERAL_PORT_FLOOR

**Value:** 32768. **Used in:** `pass_tcp_stack`. **Basis:** Measured and specification. **Verdict:** Sound.

The value is the start of the Linux default ephemeral port range; the Linux 6.18 kernel used here reports 32768 to 60999. RFC 6335 defines the dynamic range as 49152 to 65535, so the floor covers both. A connection to a port in these ranges is almost always a client reaching another client's temporary port, so recording it as a service would add noise.

Ports in `PORT_ROLES` are exempt, because a registered service can listen above the floor: EtherNet/IP uses TCP 44818, and PROFINET and EtherCAT also use ports above 32768. *Tested:* a SYN to port 44818 is recorded as a service.

### V9. PER_SOURCE_SAMPLE_LIMIT

**Value:** 100. **Used in:** `SourceCap`. **Basis:** Measured. **Verdict:** Sound.

A host states the same identity in every message of a given kind, so a sample per source establishes it. Capping per source rather than per pass ensures that a quiet host is not crowded out by busy ones before its first message appears.

*Measured* on a synthetic capture of 124,366 packets over one hour from 28 devices. A first measurement found that a cap shared across protocols lost information: with a limit of 5, both switches lost their model and switch port, because BPDUs every two seconds used up the allowance before the first CDP frame, sent every minute. With the cap keyed per device and per protocol, a limit of 1 changes a single resolved value compared with 100, and that value is a tie between two equally valid self-declared software strings from LLDP and CDP. No information is lost at any limit, so the default of 100 leaves two orders of magnitude of margin.

Where values are attributed to both ends of an exchange, the key is the host pair, so that a busy sender reaching several receivers cannot crowd out the later ones.

### V10. IP ID classification values

**Value:** `IPID_MAX_STEP` 4096, `IPID_INCREASING_SHARE` 0.75, minimum three IDs. **Used in:** `pass_ip_stack`. **Basis:** Judgement, informed by measurement. **Verdict:** Sound for their use.

The classification is recorded as raw evidence and is not used to name an operating system, so its thresholds carry little risk. Steps are taken modulo 65536, so a counter wrapping past 65535 is still recognised as increasing. *Measured:* four datagrams from an idle Linux 6.18 host carried IDs 28036, 28052, 28069 and 28070, with steps of 16, 17 and 1. The step limit of 4096 allows a busy host to send many packets that the sensor does not observe between two that it does, and requiring three quarters of steps to be increases tolerates occasional interleaving.

### V11. PORT_ROLES entries

**Used in:** `pass_tcp_stack`, `pass_services`, and indirectly `pass_zones`. **Verdict:** Sound, with one entry unverified.

**Registered with IANA for the stated service** (specification): 21, 22, 23, 25, 53, 67, 69, 80, 88, 104 (DICOM, registered as `acr-nema`), 111, 123, 137, 139, 161, 389, 443, 445, 502, 514, 515, 548, 554, 631, 636, 1433, 1723, 1812, 1883, 1900, 2049, 2404, 2575, 2762 (`dicom-tls`), 3268, 3306, 3389, 4840, 5060, 5061, 5355, 5432, 5900, 5985, 5986, 8080, 9100, 11112, 20000, 44818, 47808. Port 2762 is registered by both IANA and the DICOM standard for the DICOM upper layer protocol over TLS.

**Used for the stated service by established convention rather than IANA registration** (published data):

| Port | Service | Evidence |
|---|---|---|
| 102 | S7comm | Siemens S7 runs over ISO-on-TCP on 102, listed in ICS port references. |
| 1911 | Niagara Fox | Tridium's Fox protocol default, listed in ICS port references and security advisories. |
| 1962 | PCWorx | Phoenix Contact's PCWorx protocol, listed in ICS port references. |
| 1521 | Oracle database | Oracle's listener default by convention. |
| 8443 | alternative HTTPS | Convention. |

**Not verified here:** 3671 as KNXnet/IP, which is widely documented as the KNX default but was not checked against the registry.

Port 68 is absent deliberately. A DHCP client sends from 68 to the server's 67, so the client is recognised through the destination port 67, and listing 68 would record every client as offering a DHCP service.

### V12. UDP_PEER_PORTS entries

**Value:** 47808, 5353, 137, 138, 123. **Used in:** `pass_services`. **Basis:** Specification. **Verdict:** Sound.

The rule fires only when a datagram's source and destination ports are equal, so it identifies protocols where both parties conventionally use the same port. BACnet/IP devices send and receive on 47808. RFC 6762 has mDNS responders send from 5353. NetBIOS name and datagram services exchange broadcasts between identical ports 137 and 138. NTP in symmetric mode uses 123 at both ends; client mode uses an ephemeral source and is handled by the other rules. Ports whose two ends conventionally differ, such as DHCP and LLMNR, are omitted because the rule could never fire for them.

### V13. ZONE_HINTS membership and order

**Used in:** `pass_zones`. **Basis:** Judgement. **Verdict:** Sound with caveat.

Each marker is a protocol whose presence characterises a type of network: industrial protocols mark OT segments, DICOM and HL7 mark clinical segments, directory and file-sharing protocols mark IT segments, and MQTT, RTSP, SSDP and SIP mark device segments. The assignment reflects typical deployment rather than any standard, and a mixed segment is classified by whichever marker set it overlaps most.

The order `ot`, `clinical`, `it`, `iot` decides ties. It resolves ties toward the zones where a misclassification is most costly, which is the conservative outcome for segmentation analysis.

### V14. MDNS_SERVICE_TYPES entries

**Used in:** `_harvest_service_types`. **Basis:** the service names are registered DNS-SD service types; the device mapping is judgement. **Verdict:** Sound with caveat.

The device mapping is reliable where a service is specific to one kind of device: `_ipp` and `_pdl-datastream` for printers, `_uscan` for scanners, `_googlecast` for media receivers. `_http` and `_https` are advertised by almost any device with a web interface, so they record only the service and no device class.

### V15. BANNER_DEVICE_HINTS entries

**Used in:** `_banner_device_type`. **Basis:** Judgement. **Verdict:** Sound with caveat.

Each entry is a term that commonly appears in the self-description of that kind of device. Matching must begin at a word boundary. *Tested:* "backups" no longer matches `ups`, "iPhone" no longer matches `phone`, "APC Smart-UPS" still matches `ups`, "Cisco IP Phone" still matches `phone`, and the SSDP string `Samsung-SmartTV` matches the variant `smarttv`. Generic terms such as `switch`, `controller` and `gateway` can still match descriptions of other things, and variants not yet seen in real captures will be missed; entries should be added from observed banners.

### V16. BANNER_OS_HINTS entries

**Used in:** `_banner_os`. **Basis:** Judgement, based on how vendors describe their own software. **Verdict:** Sound with caveat.

The entries are the product names vendors place in their own descriptions, such as `Cisco IOS Software` in Cisco sysDescr and LLDP strings. The order places specific names before general ones: `ios-xe` before `cisco ios`, `windows ce` before `windows`, and `linux` last, because many embedded descriptions mention Linux alongside a more specific platform. Word-start matching prevents short entries such as `aix` from matching inside other words.

### V17. EMBEDDED_DEVICE_CLASSES entries

**Used in:** `refine_ambiguous`. **Basis:** Judgement. **Verdict:** Sound with caveat.

The set lists the device types the code can emit that denote purpose-built hardware rather than a general-purpose computer. `gateway`, `controller` and `iot device` are broad and could describe software running on a server; the others are specific.

### V18. SSH_OS_HINTS entries

**Used in:** `pass_banners`. **Verdict:** see the table.

| Term | Evidence | Verdict |
|---|---|---|
| `ubuntu`, `debian`, `raspbian` | These distributions append their package version, such as `Ubuntu-3ubuntu13`, to the OpenSSH banner. | Sound |
| `sun_ssh` | Solaris shipped an SSH server that identifies as `Sun_SSH`. | Sound |
| `dropbear` | Dropbear is common on embedded Linux; the mapping is an inference, filed at T2. | Sound with caveat |
| `cisco` | Cisco devices identify as `Cisco-` followed by a version. | Sound |
| `rosssh` | MikroTik RouterOS identifies as `SSH-2.0-ROSSSH`, confirmed in published banner captures. | Sound |
| `windows` | The Windows port of OpenSSH identifies as `OpenSSH_for_Windows`. | Sound |
| `freebsd`, `netbsd`, `openbsd` | Not verified here. OpenBSD's OpenSSH is believed to identify without an operating system suffix, in which case that entry never matches, which is harmless. | Unverified |

### V19. Field separators

**Value:** comma in `first()`; tab in `tsh()`. **Basis:** Specification of tshark's output. **Verdict:** Sound.

tshark joins repeated occurrences of a field with a comma by default, which is why `first()` splits on commas. Fields are separated with tabs because values, including distinguished names and User-Agent strings, contain commas but essentially never tabs.

### V20. Process timeouts and message length

**Value:** a ten-second wait before `kill()`; 300 characters of standard error. **Basis:** Judgement. **Verdict:** Sound.

Ten seconds is ample for tshark to exit after its output pipe is closed. The 300-character limit keeps warnings readable and does not affect results.

### V21. Values ignored by add

**Value:** `None`, the empty string, and `unknown`. **Basis:** Judgement. **Verdict:** Sound. Recording an absent value would create evidence that asserts nothing. Integer zero is accepted, because a hop count of zero is meaningful.

### V22. Multicast MAC test

**Value:** the least significant bit of the first octet. **Used in:** `pass_inventory`. **Basis:** Specification. **Verdict:** Sound.

IEEE 802 marks a group address, multicast or broadcast, by this bit. It covers IPv4 multicast (`01:00:5e`, RFC 1112), IPv6 multicast (`33:33`, RFC 2464), the IEEE reserved addresses used by STP and LLDP (`01:80:c2`), Cisco's CDP address (`01:00:0c`) and broadcast. A valid frame never carries a group address as its source, so the check is defensive.

### V23. OUI guard pattern

**Value:** a pattern rejecting vendor strings that are themselves three hexadecimal bytes. **Used in:** `pass_inventory`. **Basis:** Judgement. **Verdict:** Sound. It prevents an unresolved prefix from being recorded as a vendor name.

### V24. TCP option kinds and names

**Value:** kinds 0, 1, 2, 3, 4, 5 and 8, named `eol+N`, `nop`, `mss`, `ws`, `sok`, `sack`, `ts`. **Used in:** `_parse_tcp_options`. **Basis:** Specification and published data. **Verdict:** Sound.

Kind 0 ends the option list, kind 1 is a no-operation byte and kind 2 is the maximum segment size (RFC 9293). Kind 3 is window scale and kind 8 is timestamps (RFC 7323). Kind 4 is SACK permitted and kind 5 is SACK (RFC 2018). The names are p0f's, so that a parsed layout can be compared directly with the transcribed signatures.

### V25. Family fallback rules

**Value:** at TTL 64, timestamps and a window scale option present means Linux, BSD or macOS; otherwise embedded. Filed at T5. **Used in:** `pass_tcp_stack`. **Basis:** Published data. **Verdict:** Sound with caveat.

All 27 Linux, BSD and macOS SYN signatures in the transcribed p0f table carry both options, while minimal embedded stacks usually omit them. The only Unix exception, Solaris 10, has its own exact signature and is matched before the fallback is reached. A general-purpose system configured without timestamps would fall into the embedded label, which is a known limitation of any rule based on option presence.

### V26. Timing thresholds

**Value:** at least 8 connections; coefficient of variation below 0.15 is periodic, above 0.6 is bursty. **Used in:** `_record_timing`. **Basis:** Derived. **Verdict:** Reasonable; not validated on real traffic.

The coefficient of variation is the standard deviation of the gaps divided by their mean. Two reference points anchor the thresholds:

- **Random arrivals give 1.0.** Independent random events form a Poisson process, whose gaps are exponentially distributed with a standard deviation equal to the mean. Human-driven and event-driven traffic tends toward this.
- **Periodic arrivals give almost 0.** For a poller with period P whose events each carry independent timing jitter of standard deviation σ, each gap has variance 2σ², so the coefficient is √2 σ / P.

A threshold of 0.15 therefore corresponds to per-event jitter of about 10.6 percent of the period, loose enough for real industrial pollers yet far from random behaviour. A threshold of 0.6 sits well below the Poisson value, so traffic above it is clearly irregular. The band between is left unclassified on purpose.

Eight connections give seven gaps. A standard deviation estimated from seven values has a relative standard error of roughly 1/√12, about 29 percent, so a true coefficient of 0.10 would typically be measured between 0.07 and 0.13, which stays on the right side of 0.15. Requiring more connections would sharpen the estimate but exclude slower pollers from short captures. The synthetic capture cannot validate these thresholds, because its generator set the jitter of every device.

### V27. Excluded IPv4 addresses

**Value:** destinations 224.0.0.0 to 239.255.255.255, and the source 0.0.0.0. **Used in:** `pass_ip_stack`; 0.0.0.0 also in `pass_inventory`. **Basis:** Specification. **Verdict:** Sound.

The destination range is the IPv4 multicast block, 224.0.0.0/4, defined in RFC 5771. Discovery protocols sent to it set their TTL by rule rather than by operating system: RFC 6762 requires 255 for mDNS, and SSDP uses a small value to scope its announcements. The source 0.0.0.0 means "this host" and may be used only while a host is acquiring an address (RFC 1122), which is what a DHCP client does, so it identifies no particular host.

### V28. System port boundary

**Value:** 1024. **Used in:** `pass_services`. **Basis:** Specification. **Verdict:** Sound.

RFC 6335 defines ports 0 to 1023 as system ports, assigned to well-known services and not used as ephemeral sources by mainstream operating systems. A datagram sent from one of them is therefore a service answering. Registered services above 1023, such as HL7 on 2575, are still recognised through the destination port of the requests sent to them.

### V29. DICOM and HL7 framing values

**Used in:** `pass_clinical`. **Basis:** Specification. **Verdict:** Sound.

DICOM PDU type 1 is A-ASSOCIATE-RQ and type 2 is A-ASSOCIATE-AC (DICOM PS3.8). Application entity titles occupy fixed 16-byte fields padded with spaces, which is why they are stripped. HL7 v2 messages over TCP are framed by the Minimal Lower Layer Protocol, which starts each message with 0x0B and ends it with 0x1C 0x0D, which is why 0x0B is stripped. In the MSH segment the field separator itself counts as MSH-1, so after splitting on `|`, index 2 is MSH-3, index 3 is MSH-4 and index 4 is MSH-5.

### V30. Certificate name values

**Value:** handshake types 1 and 11; OID 2.5.4.3; the string types in `TEXT_TYPES`; the first certificate in the message. **Used in:** `pass_tls`, `_rdn_text`. **Basis:** Specification. **Verdict:** Sound.

Handshake type 1 is ClientHello and type 11 is Certificate (RFC 8446, unchanged from RFC 5246). In a Certificate message the sender's own certificate comes first, followed by any chain, which is why the first is used. OID 2.5.4.3 is the commonName attribute type. Names may be encoded as any of the directory string types, so all are accepted. *Tested:* a certificate created with current tooling encoded its names as UTF8String, and the subject common name, subject alternative name and a derived device type were extracted correctly, with the issuer's organisation not mistaken for the subject.

### V31. Truncation lengths

**Value:** 60 characters for User-Agent, 80 for certificate names and SNI, 100 for FTP and SMTP greetings, 120 for descriptions and software strings. **Basis:** Judgement. **Verdict:** Sound. These keep the CSV output readable. Each limit is well above the point at which the identifying part of such strings ends.

### V32. FTP and SMTP greeting code

**Value:** reply code 220. **Used in:** `pass_banners`. **Basis:** Specification. **Verdict:** Sound.

Both protocols have the server send a 220 service-ready reply when a connection opens, and servers conventionally identify themselves in it (RFC 959 for FTP, RFC 5321 for SMTP). Reading only that reply excludes the many later replies that carry no identifying text.

### V33. SIP, NetBIOS and SSDP parsing values

**Used in:** `pass_banners`. **Verdict:** Sound with caveat.

- **SIP:** the model is taken as the text before the first `/` and the vendor as the text before the first `-`. This matches the common `Vendor-Model/Version` form, as in `Cisco-CP8841/12.5.1`, but is a judgement and fails on other forms.
- **NetBIOS:** Wireshark shows the sixteenth byte of a NetBIOS name, a service type suffix, as `<NN>`, so the text before `<` is the host name.
- **SSDP:** UDP port 1900 and multicast address 239.255.255.250 are fixed by the UPnP Device Architecture.

### V34. SNMP object identifiers

**Value:** 1.3.6.1.2.1.1.1, .5 and .6. **Used in:** `_harvest_snmp`. **Basis:** Specification. **Verdict:** Sound.

These are sysDescr, sysName and sysLocation in the system group of the SNMPv2 MIB (RFC 3418). Scalar objects are read with an instance suffix of `.0`, which is removed before comparison. *Tested:* a response mixing string, object identifier and further string values yielded the correct hostname and location.

### V35. Census name pattern

**Value:** lines containing a colon whose first word consists of lowercase letters, digits, underscores, dots and hyphens. **Used in:** `protocol_census`. **Basis:** Judgement, from the observed format of tshark's protocol hierarchy output. **Verdict:** Sound with caveat. If a future tshark release changes that format, the census returns nothing and every pass runs, which is slower but safe.

### V36. refine_ambiguous thresholds and labels

**Value:** window 16384 or more with at least two of scaling, timestamps and SACK is a general-purpose stack; window 8192 or less with none is a minimal one. **Used in:** `refine_ambiguous`. **Basis:** Judgement. **Verdict:** Weak.

The argument is that general-purpose stacks advertise large windows and modern options, while minimal embedded stacks advertise small windows and few options. Hosts with windows between 8193 and 16383, or with mixed features, deliberately remain ambiguous. The thresholds were checked only against synthetic profiles. The labels name categories rather than products, consistent with [V7](#v7-ambiguous_ttl255-label): a feature-rich TTL-255 stack is most likely a network operating system or legacy Unix, and a minimal one an embedded device.

### V37. Zone tie breaking

**Basis:** Judgement. **Verdict:** Sound. Covered in [V13](#v13-zone_hints-membership-and-order).

### V38. Conflict attributes

**Value:** conflicts are reported for `os`, `vendor`, `hostname` and `model` only. **Used in:** `write_outputs`. **Basis:** Judgement. **Verdict:** Sound.

A device has one operating system, one vendor, one name and one model, so disagreement between sources on these is informative. Other attributes such as `service`, `role` and `software` legitimately hold several values for one device, so reporting them would flag nearly every device.

### V39. Scoring families and aliases

**Used in:** `vendor_ok`, `os_ok`. **Basis:** Published data and judgement. **Verdict:** Sound; scoring only.

Each vendor alias group joins names that refer to one manufacturer. Some reflect acquisitions or brands: Schneider Electric acquired Telemecanique, Oracle acquired Sun Microsystems, and Allen-Bradley is a Rockwell Automation brand. Others reflect Wireshark's short manufacturer names, observed in this project's output to be truncated to twelve characters, as in `Telemecaniqu`, `HewlettPacka` and `RockwellAuto`.

Operating systems are scored by family because the extractor reports a version only where a signature supports it, and a truth file naming a specific product would otherwise mark a correct family label wrong. Family terms are matched as substrings: `ios` alone is not a term, since it would match Cisco IOS as Apple, so Apple is identified by `mac os`, `macos`, `iphone` and `ipad`. None of this affects the extractor's output.

### V40. Scoring display limits

**Value:** up to 15 mismatches and 3 extra MACs are printed. **Basis:** Judgement. **Verdict:** Sound. Display only.

---

## 31. Open issues and limitations

Each item states what is known and how it was established.

**1. The rule for current Windows rests on secondary sources.** Several secondary sources report that Windows 10 and 11 send a 65535 window with scale 8, and the rule is filed at T4 accordingly. No source was found for the 64240 window also seen from Windows hosts, which therefore receives only the family label. A capture from Windows hosts of known version would settle both. See [V5](#v5-rules-for-current-systems).

**2. The rule for current Linux rests on one measured kernel.** It was measured on Linux 6.18 and agrees with a secondary report for Linux 5.x. See [V5](#v5-rules-for-current-systems).

**3. The p0f database dates from 2016, and its quirks are not used.** Systems released since then match only the documented rules or receive a family label. p0f also matches on quirks such as the DF flag and IP ID behaviour, which the signature key omits. See [V3](#v3-p0f-signature-tables).

**4. Some table entries are unverified.** Port 3671 as KNXnet/IP, and the `freebsd`, `netbsd` and `openbsd` SSH hints, were not checked against a source. An incorrect SSH hint never matches, which is harmless.

**5. Several thresholds are unvalidated on real traffic.** The timing thresholds and the stack-richness thresholds in `refine_ambiguous` are reasoned but were checked only against synthetic data. See [V26](#v26-timing-thresholds) and [V36](#v36-refine_ambiguous-thresholds-and-labels).

**6. The JSON passes depend on tshark's output layout.** `tsh_json` relies on tshark writing each packet as an object at two-space indent. If a future release changes that layout, the SNMP and certificate reads would silently return nothing. The symptom is `snmp` missing from the banners summary, or `tls` reporting `none found`, on a capture known to contain them.

**7. Banner matching is term-based.** Generic terms such as `switch`, `controller` and `gateway` can match descriptions of other things, and variants absent from the tables are missed. See [V15](#v15-banner_device_hints-entries).

**8. Spanning tree may multiply switches.** Many switches send each BPDU from the MAC of the individual port, so one switch may appear as several assets, and the root bridge comparison rarely succeeds on real equipment.

**9. Identity is keyed on MAC address.** Hosts behind network address translation collapse into a single entry, and routers appear to own every address behind them.

**10. Vendor names depend on Wireshark's manufacturer database.** An outdated Wireshark installation degrades vendor attribution without any error.

**11. The industrial pass has not been exercised.** No capture used during development contained CIP, S7comm or IEC 60870-5-104, so `pass_industrial` has been checked only for syntax and field names.

**12. The synthetic benchmark measures family-level agreement.** Its generator uses invented stacks for several device types, which no published signature matches, and the scorer compares operating systems by family. A high operating system score on it shows that the extraction logic works, not that version-level labels are correct for real equipment. Validation against captures of real devices of known identity is the remaining step.

---

## 32. Extending the code

### Adding a pass

```python
def pass_example(pcap, inv):
    """One-line summary of what the protocol reveals."""
    c = defaultdict(int)
    cap = SourceCap()
    for ip, field_a in tsh(pcap, ["ip.src", "proto.field_a"], "proto"):
        ip = first(ip)
        if not ip or not cap.take(ip):
            continue
        if field_a:
            inv.add_by_ip(ip, "attribute", first(field_a), "proto-field-a", T1)
            c["proto"] += 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    print(f"  example        {summary if summary else 'none found'}")
```

Then:

1. Add it to the pass tuple in `main()`, respecting the ordering constraints in section 2.
2. Add an entry to `PASS_REQUIREMENTS` so the census can skip it.
3. Add any new attribute to `ATTRS` if it should appear in `assets.csv`.
4. Give each `add()` call a source label that is unique and specific, so it can be traced from `evidence.csv`.
5. Choose the tier by the convention in section 5, and add a justification entry to section 30 for any fixed value introduced.

Use `SourceCap` whenever the pass reads payloads or repeated announcements, and key it on whatever the values are attributed to. Use `tsh_json` instead of `tsh` when values that belong together would otherwise be listed in separate fields.

Because every pass costs a full read, prefer adding fields and a clause to the filter of an existing pass over adding a new pass.

Confirm field names exist before relying on them. A misspelled field makes tshark fail, and a correctly spelled field that the dissector never populates silently yields empty strings:

```bash
tshark -G fields | grep "^F.*proto\."
tshark -r capture.pcap -Y proto -T fields -e proto.field_a
```

### Adding a stack signature

Prefer regenerating `P0F_SYN` and `P0F_SYNACK` from a newer p0f database, with the exclusions in [V3](#v3-p0f-signature-tables), over editing entries by hand. Every entry should trace to that source.

For a system the database lacks, add a condition to `_stack_rule()` only with evidence: a capture of a host of known identity, or a citable source. File it at T3 if measured and at T4 if the evidence is secondary, and record the evidence in [V5](#v5-rules-for-current-systems). The `stack_raw` column of `assets.csv` shows every host's signature, including its option layout, which is the quickest starting point:

```bash
tshark -r capture.pcap -Y "tcp.flags.syn==1" \
  -T fields -e ip.src -e ip.ttl -e tcp.window_size_value -e tcp.options
```

### Adding a service or zone

Add the port to `PORT_ROLES` only with a registration or documented convention, and record it in [V11](#v11-port_roles-entries). If the service identifies a zone, add its name to the matching set in `ZONE_HINTS`. If it identifies purpose-built hardware and appears as a device type, add that device type to `EMBEDDED_DEVICE_CLASSES`.

### Adding banner matches

Insert entries into `BANNER_DEVICE_HINTS` or `BANNER_OS_HINTS` above any more general entry that would otherwise match first. Prefer terms taken from banners actually observed.

### Verifying a change

```bash
python3 extract.py capture.pcap --score ground_truth.csv
```

A pass reporting `none found` for a protocol known to be present almost always indicates a wrong field name. To see why a device received a value, list its evidence:

```bash
grep "<mac>" evidence.csv
```

---

## Appendix A: Evidence source index

Every value in the `source` column of `evidence.csv`, with the attributes it can carry, its tier and the function that writes it. `N` stands for a port or VLAN number, `TYPE` for a DNS-SD service type, and `DIR` for `syn` or `syn-ack`.

This table was generated from the source by locating every `add()` and `add_by_ip()` call, so it reflects the code rather than intent.

| Source label | Attribute(s) | Tier | Written by |
|---|---|---|---|
| `bacnet-iam` | bacnet_instance, device_type, vendor_id_raw | T1 | `pass_selfdeclared` |
| `bacnet-vendor-id` | vendor | T1 | `_bacnet_vendor_names` |
| `cdp-device-id` | hostname | T1 | `pass_infrastructure` |
| `cdp-platform` | model, device_type | T1 | `pass_infrastructure` |
| `cdp-port-id` | switch_port | T1 | `pass_infrastructure` |
| `cdp-software-version` | software, os, vendor | T1, T2 | `pass_infrastructure` |
| `cip-identity` | model, device_type, vendor_id_raw, serial_number, device_type_raw, firmware | T1 | `pass_industrial` |
| `dhcp-hostname` | hostname | T1 | `pass_selfdeclared` |
| `dhcp-option55` | dhcp_fingerprint | T2 | `pass_selfdeclared` |
| `dhcp-vendor-class` | vendor_class | T2 | `pass_selfdeclared` |
| `dicom-called-ae` | ae_title, device_type | T1, T2 | `pass_clinical` |
| `dicom-calling-ae` | ae_title, device_type | T1, T2 | `pass_clinical` |
| `dicom-implementation-uid` | dicom_impl_uid | T2 | `pass_clinical` |
| `dicom-implementation-version` | software | T1 | `pass_clinical` |
| `ftp-banner` | software | T1 | `pass_banners` |
| `hl7-msh-receiving-application` | application | T1 | `pass_clinical` |
| `hl7-msh-sending-application` | application | T1 | `pass_clinical` |
| `hl7-msh-sending-facility` | facility | T1 | `pass_clinical` |
| `http-server-header` | software | T2 | `pass_selfdeclared` |
| `http-user-agent` | user_agent | T2 | `pass_selfdeclared` |
| `iec104-traffic` | service | T3 | `pass_industrial` |
| `ip-header` | ip_stack_raw | T2 | `pass_ip_stack` |
| `ip-header-family` | os | T5 | `pass_ip_stack` |
| `ipp-attributes` | model, device_type, vendor | T1 | `pass_selfdeclared` |
| `ldap-bind-dn` | hostname, domain | T1 | `pass_selfdeclared` |
| `lldp-port-desc` | switch_port_desc | T1 | `pass_infrastructure` |
| `lldp-port-id` | switch_port | T1 | `pass_infrastructure` |
| `lldp-system-desc` | software, device_type, os, vendor | T1, T2 | `pass_infrastructure` |
| `lldp-system-name` | hostname | T1 | `pass_infrastructure` |
| `mdns` | hostname | T1 | `pass_selfdeclared` |
| `mdns-service_TYPE` | device_type, service | T2 | `_harvest_service_types` |
| `netbios-name` | hostname | T1 | `pass_banners` |
| `oui-registry` | vendor | T2 | `pass_inventory` |
| `port-N/client` | role | T3 | `pass_services` |
| `port-N/server` | service, role | T3 | `pass_services` |
| `rtsp-banner` | software, device_type | T1 | `pass_selfdeclared` |
| `s7comm-traffic` | service | T3 | `pass_industrial` |
| `sip-user-agent` | software, device_type, model, vendor | T1, T2 | `pass_banners` |
| `smb2` | smb_dialect | T2 | `pass_selfdeclared` |
| `smtp-banner` | software | T1 | `pass_banners` |
| `snmp-sysdescr` | software, device_type, os, vendor | T1, T2 | `_harvest_snmp` |
| `snmp-syslocation` | location | T1 | `_harvest_snmp` |
| `snmp-sysname` | hostname | T1 | `_harvest_snmp` |
| `ssdp-server-header` | software, device_type, os | T1 | `pass_banners` |
| `ssh-banner` | software, device_type | T1, T2 | `pass_banners` |
| `ssh-banner-distro` | os | T2 | `pass_banners` |
| `stp-participant` | device_type | T3 | `pass_infrastructure` |
| `stp-root` | role | T2 | `pass_infrastructure` |
| `tcp-stack-family/DIR` | os | T5 | `pass_tcp_stack` |
| `tcp-stack-p0f-exact/DIR, tcp-stack-p0f-generic/DIR` | os | T3 or T4 | `pass_tcp_stack` |
| `tcp-stack-rule/DIR` | os | T3 or T4 | `pass_tcp_stack` |
| `tcp-stack/DIR` | stack_raw | T2 | `pass_tcp_stack` |
| `timing/port-N` | behaviour, role_hint | T3, T4 | `_record_timing` |
| `tls-certificate` | cert_subject, device_type | T1, T2 | `pass_tls` |
| `tls-certificate-san` | cert_san | T1 | `pass_tls` |
| `tls-client-hello` | ja3 | T2 | `pass_tls` |
| `tls-sni` | tls_sni_requested | T2 | `pass_tls` |
| `ttl-delta` | hops_from_sensor | T3 | `pass_tcp_stack` |
| `ttl255+feature-rich-stack` | os | T3 | `refine_ambiguous` |
| `ttl255+minimal-stack` | os | T3 | `refine_ambiguous` |
| `ttl255+self-declared-device-class` | os | T4 | `refine_ambiguous` |
| `vlan-N-protocol-mix` | zone | T3 | `pass_zones` |
| `vrrp` | role, device_type | T2, T3 | `pass_infrastructure` |

## Appendix B: References

Sources used to establish the values in [section 30](#30-why-each-value-is-what-it-is).

**Registries and standards**

- IANA Service Name and Transport Protocol Port Number Registry. <https://www.iana.org/assignments/service-names-port-numbers/>
- RFC 6335, port number ranges and procedures. <https://www.rfc-editor.org/rfc/rfc6335>
- DICOM PS3.15, Annex B, registered port 2762 `dicom-tls`. <https://dicom.nema.org/dicom/2013/output/chtml/part15/sect_B.3.html>
- DICOM PS3.8, upper layer protocol, PDU types and application entity titles.
- RFC 9293 (TCP), RFC 7323 (window scale and timestamps), RFC 2018 (selective acknowledgement): TCP option kinds.
- RFC 1122, the unspecified source address 0.0.0.0.
- RFC 3418, SNMPv2 MIB system group object identifiers.
- RFC 5771, IPv4 multicast address block. RFC 1112 and RFC 2464, multicast MAC address mapping for IPv4 and IPv6.
- RFC 6762, mDNS, including the required TTL of 255.
- RFC 8446, TLS handshake message types and certificate order.
- RFC 959 (FTP) and RFC 5321 (SMTP), 220 service-ready greeting.
- HL7 Version 2 Minimal Lower Layer Protocol framing. UPnP Device Architecture, SSDP address and port.

**Published data**

- p0f 3.09b signature database, `p0f.fp`, distributed with p0f; installed at `/etc/p0f/p0f.fp` on Debian and Ubuntu.
- Default initial TTL tables by operating system. <http://www.nagorsen.biz/ttl_default.htm>, <http://www.noahdavids.org/self_published/TTL_values.html>
- ICS protocol port reference. <https://github.com/gnebbia/nmap_tutorial/blob/master/sections/ics_scada.md>
- Shadowserver accessible ICS report, protocol and port list. <https://www.shadowserver.org/what-we-do/network-reporting/accessible-ics-report/>
- MikroTik RouterOS SSH identification string `SSH-2.0-ROSSSH`. <https://www.lisenet.com/2024/ssh-hardening-on-mikrotik-l009uigs-2haxd/>
- VxWorks network stack documentation, BSD 4.4-derived implementation. <https://daq00.triumf.ca/~daqweb/doc/vxworks/tornado2/docs/vxworks/netguide/c-tcpip3.html>

**Secondary sources for systems newer than the p0f database**

- Initial window sizes of current Windows and Linux. <https://pydoll.tech/docs/deep-dive/fingerprinting/network-fingerprinting/>
- Linux 5.x initial window 64240; Windows 65535. <https://www.systemshardening.com/articles/network/passive-os-fingerprinting-hardening/>

**Measurements made for this guide**

On a Linux 6.18 kernel with interface MTU 1400, and on a synthetic capture of 124,366 packets over one hour from 28 devices.

| Measurement | Result |
|---|---|
| TCP SYN to an external host | TTL 64, window 65280, MSS 1360, options MSS, SACK permitted, timestamps, NOP, window scale 9 |
| `ip_local_port_range` | 32768 to 60999 |
| `ip_default_ttl` | 64 |
| Four UDP datagrams to one destination | DF set; IP IDs 28036, 28052, 28069, 28070 |
| Per-source sample limit of 1 against 100 | One resolved value differs, a tie between two equally valid self-declared strings |
| Constructed SYNs for Linux 3.11+, Windows 7, Mac OS X, FreeBSD 9 | Each matched the expected p0f label |
| DICOM association request and accept | Each host received only its own title |
| SNMP response mixing value types | Correct hostname and location |
| Certificate with UTF8String names and a SAN | Subject common name and SAN extracted; issuer not mistaken for subject |
