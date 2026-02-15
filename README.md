# SoftRFP - Python

A Python implementation of the SoftRfp virtual DECT RFP (Radio Fixed Part) simulator. Connects to a Mitel OMM (Open Mobility Manager) and emulates an RFP device over the AaMiDe protocol.

Supports connecting as license RFPs, automatic re-enrollment, and running multiple virtual RFPs concurrently from a single process.

## Requirements

- Python 3.10+
- `cryptography` package

## Installation

```bash
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install .
```

## Quick Start

The simplest way to run is to point it at your OMM and config file. Without `-m`, it reads all license RFP MACs from the config and connects them all concurrently:

```bash
python -m virtualrfp -o 192.168.1.100 -c /path/to/omm_conf.txt
```

To connect a single specific RFP:

```bash
python -m virtualrfp -m 001122334455 -o 192.168.1.100 -c /path/to/omm_conf.txt
```

## Usage

```bash
python -m virtualrfp -o <OMM_IP> [-m <MAC>] [-c <CONFIG>] [options]
```

### Parameters

| Flag | Long | Required | Description |
|------|------|----------|-------------|
| `-m` | `--mac` | No | RFP MAC address. If omitted, reads license RFP MACs from omm_conf.txt and connects all of them |
| `-o` | `--omm` | Yes | OMM IP address |
| `-k` | `--key` | No | RFPA (Blowfish encryption key) in hex |
| `-c` | `--config` | No | Path to omm_conf.txt (default: `../omm_conf.txt`) |
| `-d` | `--debug` | No | Dump raw packets in hex |
| | `--sw-version` | No | Software version string (auto-detected from omm_conf.txt if not set) |
| | `--hw-type` | No | Hardware type to report (e.g. `RFP35`, `RFP32`, `PC`). Default: `RFP35` |
| | `--root-pw-hash` | No | OMM root password hash for re-enrollment (auto-read from omm_conf.txt if not set) |
| | `--force-enroll` | No | Send an invalid signature to force re-enrollment |

### Examples

```bash
# Connect all license RFPs from config (simplest usage)
python -m virtualrfp -o 192.168.1.100 -c /path/to/omm_conf.txt

# Connect a single RFP with debug output
python -m virtualrfp -m 001122334455 -o 192.168.1.100 -c /path/to/omm_conf.txt -d

# Provide RFPA key directly (bypasses config file lookup)
python -m virtualrfp -m 001122334455 -o 192.168.1.100 -k abcdef01234567...

# Override hardware type
python -m virtualrfp -m 001122334455 -o 192.168.1.100 --hw-type RFP32
```

If installed as a package, the `virtualrfp` command is also available:

```bash
virtualrfp -o 192.168.1.100 -c /path/to/omm_conf.txt
```

## How It Works

1. Opens a TCP connection to the OMM on port 16321
2. Receives a random authentication challenge packet
3. Sends a `SYS_INIT` message containing the RFP MAC, capabilities, AES-encrypted metadata, and an MD5 signature
4. Handles the init response:
   - **ACK** -- RFP is already enrolled, proceed to encryption
   - **SYS_RFP_AUTH_KEY (0x0124)** -- New RFPA key for first-time enrollment
   - **SYS_RFP_RE_ENROLEMENT (0x0125)** -- RFPA encrypted with AES-256-ECB, decrypted using the OMM root password hash
   - **SYS_RESET (0x0121)** -- Auto-reconnects after a delay
5. Initializes Blowfish CBC encryption using the RFPA key (different key slices for RX and TX)
6. Sends `SYS_ENCRYPTION_CONF` to signal encrypted mode is active
7. Processes encrypted messages: heartbeats, license timers, and all other AaMiDe message types

### RFPA Key

The RFPA is a 64-byte Blowfish key used for the encrypted session. It can be obtained in several ways (checked in order):

1. **Init response** -- The OMM may send the key as `SYS_RFP_AUTH_KEY` (new enrollment) or `SYS_RFP_RE_ENROLEMENT` (re-enrollment with AES decryption)
2. **Local key store** -- Previously obtained keys are cached in `.virtualrfp_keys.json` in the working directory
3. **Config file** -- Loaded from the `RFPA` section of omm_conf.txt (decrypted using the MAC as Blowfish ECB key)
4. **`-k` flag** -- Pass the encrypted RFPA in hex directly
5. **Wait mode** -- If no key is available, the connection stays open waiting for the OMM to send one

### Re-enrollment

When the OMM sends `SYS_RFP_RE_ENROLEMENT`, the RFPA is encrypted with AES-256-ECB using a key derived from the authentication challenge and the OMM root password hash. The root password hash is automatically read from the `UA` section of omm_conf.txt, or can be provided manually with `--root-pw-hash`.

### Multi-RFP Mode

When no `-m` flag is given, the tool reads the license RFP MAC addresses from the `LIC` section of omm_conf.txt and connects all of them concurrently as separate async tasks. Log output is prefixed with the last 4 hex digits of each MAC for identification (e.g. `[39F3]`, `[3E45]`).

### Auto-detection

The following values are automatically read from omm_conf.txt when not explicitly provided:

- **Software version** -- From the config file header (e.g. `SIP-DECT 8.1SP3-FK24`)
- **Protocol version** -- Derived from the software version
- **Root password hash** -- From the `UA` section, `root` user entry
- **License RFP MACs** -- From the `LIC` section

## Project Structure

```
virtualrfp/
├── pyproject.toml              # Package configuration
├── requirements.txt            # cryptography>=41.0.0
├── README.md
└── virtualrfp/
    ├── __init__.py
    ├── __main__.py             # CLI entry point (multi-RFP support)
    ├── blowfish.py             # Blowfish cipher (ECB/CBC)
    ├── hex_encoding.py         # Hex encoding and endian swap utilities
    ├── messages.py             # AaMiDe protocol message classes
    ├── omm_conf_reader.py      # OMM config file parser (with MD5 validation)
    └── virtual_rfp.py          # Core VirtualRfp client
```

## Origin

Python port of the C# [SoftRfp](https://github.com/eventphone/rfpproxy) project from the rfpproxy framework, originally presented at 36c3.
