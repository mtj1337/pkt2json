# pkt2json

> Convert Cisco Packet Tracer `.pkt` / `.pka` files to **JSON** — free, offline, no license key required.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pkt2json.py)
[![PT versions](https://img.shields.io/badge/Packet%20Tracer-7.x%20–%209.x-blue)](README.md)

---

## Features

- **No license key** — unlike paid online converters
- **No external dependencies** — pure Python stdlib (`zlib`, `xml`, `json`)
- **Fully offline** — your files never leave your machine
- Supports **PT 7.x through 9.x** (auto-detects encryption format)
- Also ships as a **single-file HTML web app** that runs entirely in the browser
- Extracts: device configs, IP/MAC addresses, port connections, activity instructions (`.pka`)

---

## Output

```json
{
  "metadata": { "version": "9.0.0.0810", "deviceCount": 8, "linkCount": 6 },
  "devices": [
    {
      "name": "Router0",
      "type": "Router",
      "model": "ISR4331",
      "position": { "x": 740.5, "y": 298 },
      "interfaces": [
        { "name": "GigabitEthernet0/0/0", "mac": "000D.BD7C.2001", "ips": [] }
      ],
      "runningConfig": "!\nversion 16.6.4\nhostname Router\n..."
    }
  ],
  "links": [
    {
      "cableType": "eCopper",
      "from": { "device": "PC0", "port": "FastEthernet0" },
      "to":   { "device": "Switch0", "port": "FastEthernet0/1" }
    }
  ]
}
```

---

## Installation

No installation needed. Requires Python 3.8+.

```bash
git clone https://github.com/mtj1337/pkt2json
cd pkt2json
```

---

## Usage

### Python CLI

```bash
# Basic conversion  →  outputs topology.json
python3 pkt2json.py topology.pkt

# Custom output file
python3 pkt2json.py topology.pkt -o result.json

# Batch convert multiple files
python3 pkt2json.py labs/*.pkt

# Compact JSON (no indentation)
python3 pkt2json.py topology.pkt --compact
```

### Web app (browser)

Open `pkt-converter.html` in any modern browser — drag and drop your file, click **Convert**, download JSON. No server needed.

---

## How it works

| Version | Format |
|---------|--------|
| PT 7.x – 8.x | XOR counter + Qt-zlib |
| PT 9.x | Stage1 XOR → Twofish-EAX (hardcoded key) → Stage2 XOR → Qt-zlib |

The encryption keys are hardcoded in the PT binary and have been reverse-engineered by the open-source community — see [Credits](#credits).

---

## Files

| File | Description |
|------|-------------|
| `pkt2json.py` | Python CLI — zero dependencies, single file |
| `pkt-converter.html` | Browser web app — zero dependencies, single file |
| `LICENSE` | MIT |

---

## Credits

Decryption algorithm reverse-engineered by:
- **[axcheron/ptexplorer](https://github.com/axcheron/ptexplorer)** — PT 7.x/8.x legacy format
- **[Punkcake21/Unpacket](https://github.com/Punkcake21/Unpacket)** — PT 9.x Twofish-EAX format

Twofish cipher implementation derived from **Bjorn Edstrom** (Python) and **Dr. Brian Gladman** (original C).

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.

> This project is not affiliated with Cisco Systems, Inc.
> Cisco and Packet Tracer are trademarks of Cisco Systems, Inc.
