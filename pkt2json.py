#!/usr/bin/env python3
"""
pkt2json.py — Cisco Packet Tracer (.pkt/.pka) → JSON converter

Supports PT 7.x–9.x. No external dependencies (pure stdlib).

Usage:
    python pkt2json.py topology.pkt
    python pkt2json.py topology.pkt -o output.json
    python pkt2json.py topology.pkt --pretty

Credits:
    Decryption algorithm reverse-engineered by:
    - axcheron/ptexplorer  (legacy XOR format)
    - Punkcake21/Unpacket  (PT 9.x Twofish-EAX format)
"""

import argparse
import json
import struct
import sys
import zlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  TWOFISH  (pure Python, derived from Bjorn Edstrom's implementation)
#  Original C implementation by Dr Brian Gladman — MIT-compatible license
# ─────────────────────────────────────────────────────────────────────────────

_tab_5b = [0, 90, 180, 238]
_tab_ef = [0, 238, 180, 90]
_ror4   = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
_ashx   = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]
_qt0    = [[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],[2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5]]
_qt1    = [[14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],[1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8]]
_qt2    = [[11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],[4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15]]
_qt3    = [[13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10],[11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]]


def _u32(x):  return x & 0xFFFFFFFF
def _rotr(x, n): return _u32((x >> n) | (x << (32 - n)))
def _rotl(x, n): return _u32((x << n) | (x >> (32 - n)))
def _byte(x, n):  return (x >> (8 * n)) & 0xFF


def _qp(n, x):
    a0, b0 = x >> 4, x & 15
    a1, b1 = a0 ^ b0, _ror4[b0] ^ _ashx[a0]
    a2, b2 = _qt0[n][a1], _qt1[n][b1]
    a3, b3 = a2 ^ b2, _ror4[b2] ^ _ashx[a2]
    return (_qt3[n][b3] << 4) | _qt2[n][a3]


def _mds_rem(p0, p1):
    for _ in range(8):
        t  = p1 >> 24
        p1 = _u32((p1 << 8) | (p0 >> 24))
        p0 = _u32(p0 << 8)
        u  = _u32(t << 1)
        if t & 0x80: u ^= 0x014D
        p1 ^= t ^ _u32(u << 16)
        u  ^= t >> 1
        if t & 0x01: u ^= 0x014D >> 1
        p1 ^= _u32(u << 24) | _u32(u << 8)
    return p1


class _TwofishCtx:
    __slots__ = ('k_len', 'l_key', 's_key', 'q_tab', 'm_tab', 'mk_tab')
    def __init__(self):
        self.k_len  = 0
        self.l_key  = [0] * 40
        self.s_key  = [0] * 4
        self.q_tab  = [[0]*256, [0]*256]
        self.m_tab  = [[0]*256, [0]*256, [0]*256, [0]*256]
        self.mk_tab = [[0]*256, [0]*256, [0]*256, [0]*256]


def _tf_init(key: bytes) -> _TwofishCtx:
    if len(key) not in (16, 24, 32):
        raise ValueError("Twofish key must be 16, 24 or 32 bytes")
    ctx = _TwofishCtx()
    ctx.k_len = len(key) * 8 // 64  # 2, 3, or 4

    # Generate q-tables
    for i in range(256):
        ctx.q_tab[0][i] = _qp(0, i)
        ctx.q_tab[1][i] = _qp(1, i)

    # Generate MDS tables
    for i in range(256):
        f = ctx.q_tab[1][i]
        f5 = (f ^ (f >> 2) ^ _tab_5b[f & 3]) & 0xFF
        fe = (f ^ (f >> 1) ^ (f >> 2) ^ _tab_ef[f & 3]) & 0xFF
        ctx.m_tab[0][i] = _u32(f  | (f5 << 8) | (fe << 16) | (fe << 24))
        ctx.m_tab[2][i] = _u32(f5 | (fe << 8) | (f  << 16) | (fe << 24))
        f = ctx.q_tab[0][i]
        f5 = (f ^ (f >> 2) ^ _tab_5b[f & 3]) & 0xFF
        fe = (f ^ (f >> 1) ^ (f >> 2) ^ _tab_ef[f & 3]) & 0xFF
        ctx.m_tab[1][i] = _u32(fe | (fe << 8) | (f5 << 16) | (f  << 24))
        ctx.m_tab[3][i] = _u32(f5 | (f  << 8) | (fe << 16) | (f5 << 24))

    def h_fun(x, skey):
        b = [_byte(x, n) for n in range(4)]
        q = ctx.q_tab
        if ctx.k_len >= 4:
            b = [q[1][b[0]]^_byte(skey[3],0), q[0][b[1]]^_byte(skey[3],1),
                 q[0][b[2]]^_byte(skey[3],2), q[1][b[3]]^_byte(skey[3],3)]
        if ctx.k_len >= 3:
            b = [q[1][b[0]]^_byte(skey[2],0), q[1][b[1]]^_byte(skey[2],1),
                 q[0][b[2]]^_byte(skey[2],2), q[0][b[3]]^_byte(skey[2],3)]
        b = [q[0][q[0][b[0]]^_byte(skey[1],0)]^_byte(skey[0],0),
             q[0][q[1][b[1]]^_byte(skey[1],1)]^_byte(skey[0],1),
             q[1][q[0][b[2]]^_byte(skey[1],2)]^_byte(skey[0],2),
             q[1][q[1][b[3]]^_byte(skey[1],3)]^_byte(skey[0],3)]
        return _u32(ctx.m_tab[0][b[0]] ^ ctx.m_tab[1][b[1]] ^ ctx.m_tab[2][b[2]] ^ ctx.m_tab[3][b[3]])

    # Parse key words (little-endian)
    kw = list(struct.unpack_from(f'<{len(key)//4}I', key))
    me = [kw[i*2]     for i in range(ctx.k_len)]
    mo = [kw[i*2 + 1] for i in range(ctx.k_len)]
    for i in range(ctx.k_len):
        ctx.s_key[ctx.k_len - 1 - i] = _mds_rem(me[i], mo[i])

    for i in range(0, 40, 2):
        a = h_fun(_u32(0x01010101 * i),       me)
        b = _rotl(h_fun(_u32(0x01010101 * (i+1)), mo), 8)
        ctx.l_key[i]     = _u32(a + b)
        ctx.l_key[i + 1] = _rotl(_u32(a + 2*b), 9)

    # Generate mixed key table
    q, m, mk, sk = ctx.q_tab, ctx.m_tab, ctx.mk_tab, ctx.s_key
    for i in range(256):
        if ctx.k_len == 2:
            mk[0][i] = m[0][q[0][q[0][i]^_byte(sk[1],0)]^_byte(sk[0],0)]
            mk[1][i] = m[1][q[0][q[1][i]^_byte(sk[1],1)]^_byte(sk[0],1)]
            mk[2][i] = m[2][q[1][q[0][i]^_byte(sk[1],2)]^_byte(sk[0],2)]
            mk[3][i] = m[3][q[1][q[1][i]^_byte(sk[1],3)]^_byte(sk[0],3)]
        elif ctx.k_len == 3:
            mk[0][i] = m[0][q[0][q[0][q[1][i]^_byte(sk[2],0)]^_byte(sk[1],0)]^_byte(sk[0],0)]
            mk[1][i] = m[1][q[0][q[1][q[1][i]^_byte(sk[2],1)]^_byte(sk[1],1)]^_byte(sk[0],1)]
            mk[2][i] = m[2][q[1][q[0][q[0][i]^_byte(sk[2],2)]^_byte(sk[1],2)]^_byte(sk[0],2)]
            mk[3][i] = m[3][q[1][q[1][q[0][i]^_byte(sk[2],3)]^_byte(sk[1],3)]^_byte(sk[0],3)]
        else:
            mk[0][i] = m[0][q[0][q[0][q[1][q[1][i]^_byte(sk[3],0)]^_byte(sk[2],0)]^_byte(sk[1],0)]^_byte(sk[0],0)]
            mk[1][i] = m[1][q[0][q[1][q[1][q[0][i]^_byte(sk[3],1)]^_byte(sk[2],1)]^_byte(sk[1],1)]^_byte(sk[0],1)]
            mk[2][i] = m[2][q[1][q[0][q[0][q[0][i]^_byte(sk[3],2)]^_byte(sk[2],2)]^_byte(sk[1],2)]^_byte(sk[0],2)]
            mk[3][i] = m[3][q[1][q[1][q[0][q[1][i]^_byte(sk[3],3)]^_byte(sk[2],3)]^_byte(sk[1],3)]^_byte(sk[0],3)]
    return ctx


def _tf_encrypt_block(ctx: _TwofishCtx, block: bytes) -> bytes:
    a, b, c, d = struct.unpack_from('<4I', block)
    blk = [_u32(a ^ ctx.l_key[0]), _u32(b ^ ctx.l_key[1]),
           _u32(c ^ ctx.l_key[2]), _u32(d ^ ctx.l_key[3])]
    mk, lk = ctx.mk_tab, ctx.l_key
    for r in range(8):
        t0 = _u32(mk[0][_byte(blk[0],0)] ^ mk[1][_byte(blk[0],1)] ^ mk[2][_byte(blk[0],2)] ^ mk[3][_byte(blk[0],3)])
        t1 = _u32(mk[0][_byte(blk[1],3)] ^ mk[1][_byte(blk[1],0)] ^ mk[2][_byte(blk[1],1)] ^ mk[3][_byte(blk[1],2)])
        blk[2] = _rotr(_u32(blk[2] ^ _u32(t0 + t1     + lk[4*r+8])), 1)
        blk[3] = _u32(_rotl(blk[3], 1) ^ _u32(t0 + 2*t1 + lk[4*r+9]))
        t0 = _u32(mk[0][_byte(blk[2],0)] ^ mk[1][_byte(blk[2],1)] ^ mk[2][_byte(blk[2],2)] ^ mk[3][_byte(blk[2],3)])
        t1 = _u32(mk[0][_byte(blk[3],3)] ^ mk[1][_byte(blk[3],0)] ^ mk[2][_byte(blk[3],1)] ^ mk[3][_byte(blk[3],2)])
        blk[0] = _rotr(_u32(blk[0] ^ _u32(t0 + t1     + lk[4*r+10])), 1)
        blk[1] = _u32(_rotl(blk[1], 1) ^ _u32(t0 + 2*t1 + lk[4*r+11]))
    return struct.pack('<4I', _u32(blk[2]^lk[4]), _u32(blk[3]^lk[5]),
                              _u32(blk[0]^lk[6]), _u32(blk[1]^lk[7]))


# ─────────────────────────────────────────────────────────────────────────────
#  CMAC / CTR / EAX  (pure Python, 128-bit block)
# ─────────────────────────────────────────────────────────────────────────────

BS = 16  # block size in bytes


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _lshift1(b: bytes) -> bytes:
    out, carry = bytearray(len(b)), 0
    for i in reversed(range(len(b))):
        out[i] = ((b[i] << 1) & 0xFF) | carry
        carry   = b[i] >> 7
    return bytes(out)


def _cmac_subkeys(enc):
    Rb = b'\x00' * (BS - 1) + b'\x87'
    L  = enc(b'\x00' * BS)
    K1 = _lshift1(L);  K1 = _xor(K1, Rb) if L[0] & 0x80 else K1
    K2 = _lshift1(K1); K2 = _xor(K2, Rb) if K1[0] & 0x80 else K2
    return K1, K2


def _cmac(data: bytes, enc, K1: bytes, K2: bytes) -> bytes:
    blocks = [data[i:i+BS] for i in range(0, max(len(data), 1), BS)] if data else [b'']
    if len(blocks[-1]) == BS:
        last = _xor(blocks[-1], K1); blocks = blocks[:-1]
    else:
        pad  = blocks[-1] + b'\x80' + b'\x00' * (BS - len(blocks[-1]) - 1)
        last = _xor(pad, K2);        blocks = blocks[:-1]
    X = b'\x00' * BS
    for blk in blocks:
        X = enc(_xor(X, blk))
    return enc(_xor(X, last))


def _ctr(data: bytes, enc, iv: bytes) -> bytes:
    ctr = bytearray(iv)
    out = bytearray()
    for off in range(0, len(data), BS):
        ks = enc(bytes(ctr))
        for i in reversed(range(BS)):
            ctr[i] = (ctr[i] + 1) & 0xFF
            if ctr[i]: break
        chunk = data[off:off+BS]
        out.extend(b ^ k for b, k in zip(chunk, ks))
    return bytes(out)


def _eax_decrypt(enc, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    K1, K2 = _cmac_subkeys(enc)

    def omac(prefix, payload):
        hdr = b'\x00' * (BS - 1) + bytes([prefix])
        return _cmac(hdr + payload, enc, K1, K2)

    n_tag = omac(0, nonce)
    h_tag = omac(1, b'')
    c_tag = omac(2, ciphertext)
    expected = _xor(_xor(n_tag, h_tag), c_tag)

    if expected != tag:
        raise ValueError("EAX authentication failed — file corrupted or unsupported version")

    return _ctr(ciphertext, enc, n_tag)


# ─────────────────────────────────────────────────────────────────────────────
#  PKT DECRYPTION
# ─────────────────────────────────────────────────────────────────────────────

# Hardcoded key/IV embedded by Cisco in PT 9.x binary
_PT9_KEY = bytes([137] * 16)
_PT9_IV  = bytes([16]  * 16)


def _deobf_stage1(data: bytes) -> bytes:
    L = len(data)
    return bytes(data[L-1-i] ^ ((L - i*L) & 0xFF) for i in range(L))


def _deobf_stage2(data: bytes) -> bytes:
    L = len(data)
    return bytes(b ^ ((L - i) & 0xFF) for i, b in enumerate(data))


def _qt_decompress(data: bytes) -> bytes:
    expected = struct.unpack('>I', data[:4])[0]
    return zlib.decompress(data[4:])[:expected]


def _decrypt_v9(data: bytes) -> bytes:
    """PT 9.x: deobf_stage1 → Twofish-EAX → deobf_stage2 → Qt-zlib"""
    ctx = _tf_init(_PT9_KEY)
    enc = lambda block: _tf_encrypt_block(ctx, block)

    stage1     = _deobf_stage1(data)
    decrypted  = _eax_decrypt(enc, _PT9_IV, stage1[:-16], stage1[-16:])
    stage2     = _deobf_stage2(decrypted)
    return _qt_decompress(stage2)


def _decrypt_legacy(data: bytes) -> bytes:
    """PT ≤ 8.x: simple XOR counter → Qt-zlib"""
    counter = len(data)
    out = bytearray()
    for byte in data:
        out.append(byte ^ (counter & 0xFF))
        counter -= 1
    return _qt_decompress(bytes(out))


def decrypt_pkt(data: bytes) -> bytes:
    """Decrypt a .pkt/.pka file and return raw XML bytes."""
    for fn, label in [(_decrypt_v9, 'v9'), (_decrypt_legacy, 'legacy')]:
        try:
            return fn(data)
        except Exception:
            continue
    raise ValueError("Failed to decrypt — unsupported PT version or corrupted file")


# ─────────────────────────────────────────────────────────────────────────────
#  XML → JSON
# ─────────────────────────────────────────────────────────────────────────────

def _txt(el, tag):
    found = el.find(tag)
    return found.text.strip() if found is not None and found.text else None


def _parse_running_config(rc_el):
    if rc_el is None:
        return None
    lines = rc_el.findall('LINE')
    if lines:
        return '\n'.join(l.text or '' for l in lines)
    return (rc_el.text or '').strip() or None


def _parse_device(dev_el):
    engine = dev_el.find('ENGINE')
    if engine is None:
        return None

    type_el = engine.find('.//TYPE[@model]')
    model   = type_el.get('model') if type_el is not None else None
    dev_type = engine.findtext('TYPE') or 'Unknown'
    name    = engine.findtext('NAME') or 'Unknown'
    save_ref = engine.findtext('SAVE_REF_ID') or ''

    # Position from WORKSPACE > LOGICAL
    logical = dev_el.find('WORKSPACE/LOGICAL')
    x = float(logical.findtext('X') or 0) if logical is not None else 0
    y = float(logical.findtext('Y') or 0) if logical is not None else 0

    # Configs
    running_config = _parse_running_config(engine.find('.//RUNNINGCONFIG'))
    startup_config = _parse_running_config(engine.find('.//STARTUPCONFIG'))

    # Interfaces
    interfaces = []
    for port in engine.iter('PORT'):
        mac       = port.findtext('MACADDRESS')
        port_name = port.findtext('PORT_NAME')
        port_type = port.findtext('TYPE')
        power     = port.findtext('POWER')
        bw        = port.findtext('BANDWIDTH')

        ips = [a.text.strip() for a in port.iter('ADDRESS')
               if a.text and a.text.strip() not in ('', '0.0.0.0')]

        if mac or ips or port_name:
            interfaces.append({
                'name':      port_name,
                'type':      port_type,
                'mac':       mac,
                'ips':       ips,
                'bandwidth': bw,
                'power':     power,
            })

    return {
        'name':          name,
        'type':          dev_type,
        'model':         model,
        'saveRef':       save_ref,
        'position':      {'x': x, 'y': y},
        'interfaces':    interfaces,
        'runningConfig': running_config,
        'startupConfig': startup_config,
    }


def _sanitize_xml(xml_bytes: bytes) -> bytes:
    """Strip characters invalid in XML 1.0 (control chars except tab/LF/CR)."""
    import re
    return re.sub(rb'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', b'', xml_bytes)


def xml_to_json(xml_bytes: bytes) -> dict:
    root = ET.fromstring(_sanitize_xml(xml_bytes))
    version = root.findtext('VERSION') or 'unknown'

    network = root.find('NETWORK')
    if network is None:
        raise ValueError("No NETWORK section found in file")

    # Devices
    devices, ref_map = [], {}
    for dev_el in network.findall('DEVICES/DEVICE'):
        dev = _parse_device(dev_el)
        if dev:
            devices.append(dev)
            if dev['saveRef']:
                ref_map[dev['saveRef']] = dev['name']

    # Links
    links = []
    for link_el in network.findall('LINKS/LINK'):
        cable_type = link_el.findtext('TYPE') or 'unknown'
        cable      = link_el.find('CABLE')
        if cable is None:
            continue

        froms = cable.findall('FROM')
        tos   = cable.findall('TO')
        ports = cable.findall('PORT')

        from_ref  = froms[0].text.strip() if froms else ''
        to_ref    = tos[0].text.strip()   if tos   else ''
        from_port = ports[0].text.strip() if len(ports) > 0 else ''
        to_port   = ports[1].text.strip() if len(ports) > 1 else ''

        links.append({
            'cableType': cable_type,
            'from': {'device': ref_map.get(from_ref, from_ref), 'port': from_port},
            'to':   {'device': ref_map.get(to_ref,   to_ref),   'port': to_port},
        })

    # Notes / activity (PKA files)
    notes    = [n.text.strip() for n in root.findall('.//NOTES/NOTE') if n.text]
    act_el   = root.find('ACTIVITY')
    activity = None
    if act_el is not None:
        activity = {
            'title':        act_el.findtext('TITLE'),
            'instructions': act_el.findtext('INSTRUCTIONS') or act_el.findtext('INSTRUCTION'),
        }

    return {
        'metadata': {
            'version':     version,
            'generatedAt': datetime.now(timezone.utc).isoformat(),
            'deviceCount': len(devices),
            'linkCount':   len(links),
        },
        'description': network.findtext('DESCRIPTION') or None,
        'activity':    activity,
        'notes':       notes,
        'devices':     devices,
        'links':       links,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def convert(input_path, output_path=None, pretty=True):
    data = input_path.read_bytes()

    print(f"  Decrypting {input_path.name} ({len(data):,} bytes)...", file=sys.stderr)
    xml_bytes = decrypt_pkt(data)

    print(f"  Parsing topology ({len(xml_bytes):,} bytes XML)...", file=sys.stderr)
    result = xml_to_json(xml_bytes)

    m = result['metadata']
    print(f"  Found {m['deviceCount']} devices, {m['linkCount']} links (PT {m['version']})", file=sys.stderr)

    out = output_path or input_path.with_suffix('.json')
    indent = 2 if pretty else None
    out.write_text(json.dumps(result, indent=indent, ensure_ascii=False), encoding='utf-8')
    print(f"  Saved → {out}", file=sys.stderr)
    return out


def main():
    parser = argparse.ArgumentParser(
        description='Convert Cisco Packet Tracer .pkt/.pka files to JSON',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('input', nargs='+', help='.pkt or .pka file(s)')
    parser.add_argument('-o', '--output', help='output JSON file (single input only)')
    parser.add_argument('--compact', action='store_true', help='compact JSON (no indentation)')
    args = parser.parse_args()

    if args.output and len(args.input) > 1:
        parser.error('--output can only be used with a single input file')

    ok = err = 0
    for path_str in args.input:
        p = Path(path_str)
        try:
            print(f"\n[{p.name}]", file=sys.stderr)
            out = Path(args.output) if args.output else None
            convert(p, out, pretty=not args.compact)
            ok += 1
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            err += 1

    if len(args.input) > 1:
        print(f"\nDone: {ok} converted, {err} failed", file=sys.stderr)

    sys.exit(1 if err and not ok else 0)


if __name__ == '__main__':
    main()
