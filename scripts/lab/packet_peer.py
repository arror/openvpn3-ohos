#!/opt/homebrew/bin/python3
# SPDX-License-Identifier: MPL-2.0
"""Unprivileged OpenVPN unix: TUN peer. Answers synthetic IPv4/IPv6 ICMP, UDP, and HTTP probes."""
import json, os, select, socket, struct, time
from pathlib import Path

def checksum(data):
    if len(data) & 1: data += b'\0'
    n = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while n >> 16: n = (n & 65535) + (n >> 16)
    return (~n) & 65535

def acknowledge(nonce, family):
    path = Path.cwd()/'probe.reply'
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'nonce':nonce,'family':family}))
    temporary.replace(path)

PENDING_HTTP = {}

def tcp_response(packet, size, ipv6=False):
    body = packet[size:]
    if len(body) < 20: return None
    src, dst, seq, ack, offset, flags, window, check, urgent = struct.unpack('!HHIIBBHHH', body[:20])
    if dst != 80: return None
    payload = body[(offset >> 4)*4:]
    key = ((packet[8:40] if ipv6 else packet[12:20]), src, dst)
    pending = PENDING_HTTP.get(key)
    if pending and flags & 0x10 and ack == pending[1]:
        acknowledge(pending[0], pending[2]); del PENDING_HTTP[key]
    data = b''
    if flags & 2:
        server_seq, next_seq, out_flags = 10000, seq + 1, 0x12
    elif payload:
        server_seq, next_seq, out_flags = ack, seq + len(payload), 0x19
        path = payload.split(b' ', 2)[1] if payload.startswith(b'GET ') else b''
        try: nonce = (Path.cwd()/'probe.request').read_text().strip()
        except FileNotFoundError: nonce = ''
        content = (b'ArkOvpn compressed payload. ' * 40) if os.environ.get('ARKOVPN_PROBE_LARGE') == '1' else b'OK'
        data = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(content)).encode()+b'\r\nConnection: close\r\n\r\n'+content
        if nonce and path == ('/' + nonce).encode():
            PENDING_HTTP[key] = (nonce, (server_seq + len(data) + 1) & 0xffffffff, 6 if ipv6 else 4)
    elif flags & 1:
        server_seq, next_seq, out_flags = ack, seq + 1, 0x10
    else: return None
    tcp = bytearray(struct.pack('!HHIIBBHHH', dst, src, server_seq, next_seq, 0x50, out_flags, 32768, 0, 0) + data)
    source, target = (packet[24:40], packet[8:24]) if ipv6 else (packet[16:20], packet[12:16])
    pseudo = source + target + (struct.pack('!I3xB', len(tcp), 6) if ipv6 else struct.pack('!BBH', 0, 6, len(tcp)))
    tcp[16:18] = struct.pack('!H', checksum(pseudo + bytes(tcp)))
    if ipv6:
        return struct.pack('!IHBB16s16s', 6 << 28, len(tcp), 6, 64, source, target) + tcp
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, source, target))
    header[10:12] = struct.pack('!H', checksum(bytes(header)))
    return bytes(header + tcp)

def response(packet):
    if not packet: return None
    # Unix TUN packets carry raw layer-3 data, no OS AF header.
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 28:
        size = (packet[0] & 15) * 4
        if len(packet) < size + 8: return None
        header, body = bytearray(packet[:size]), bytearray(packet[size:])
        proto = header[9]
        if proto == 6: return tcp_response(packet, size)
        if proto == 1 and body[0] == 8:
            body[0] = 0; body[2:4] = b'\0\0'
            body[2:4] = struct.pack('!H', checksum(bytes(body)))
        elif proto == 17:
            body[:4] = body[2:4] + body[:2]; body[6:8] = b'\0\0'
        else: return None
        header[12:20] = header[16:20] + header[12:16]
        header[8] = 64; header[10:12] = b'\0\0'
        header[10:12] = struct.pack('!H', checksum(bytes(header)))
        return bytes(header + body)
    if version == 6 and len(packet) >= 48:
        header, body = bytearray(packet[:40]), bytearray(packet[40:])
        proto = header[6]
        if proto == 6: return tcp_response(packet, 40, True)
        if proto == 58 and body[0] == 128:
            body[0] = 129; offset = 2
        elif proto == 17:
            body[:4] = body[2:4] + body[:2]; offset = 6
        else: return None
        header[8:40] = header[24:40] + header[8:24]
        body[offset:offset+2] = b'\0\0'
        pseudo = bytes(header[8:40]) + struct.pack('!I3xB', len(body), proto)
        body[offset:offset+2] = struct.pack('!H', checksum(pseudo + bytes(body)))
        return bytes(header + body)
    return None

if __name__ == '__main__':
    peer = socket.socket(fileno=int(os.environ['TUNTAP_SOCKET_FD']))
    pending = ''
    last_sent = 0
    work = Path.cwd()
    while True:
        if os.getppid() == 1: break
        try: nonce = (work/'probe.request').read_text().strip()
        except FileNotFoundError: nonce = ''
        if nonce and os.environ.get('ARKOVPN_PROBE_LARGE') != '1' and time.monotonic() - last_sent > .3:
            payload = ('ARKOVPN:' + nonce).encode()
            body = bytearray(struct.pack('!BBHHH', 8, 0, 0, 0x4152, 1) + payload)
            body[2:4] = struct.pack('!H', checksum(bytes(body)))
            header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(body), 0, 0, 64, 1, 0, socket.inet_aton('10.247.0.1'), socket.inet_aton('10.247.0.2')))
            header[10:12] = struct.pack('!H', checksum(bytes(header)))
            peer.send(header + body)
            pending = nonce; last_sent = time.monotonic()
        if not select.select([peer], [], [], .1)[0]: continue
        packet = peer.recv(65535)
        if not packet: break
        with (work/'packets.log').open('a') as log: log.write('version=%d bytes=%d proto=%d\n' % (packet[0] >> 4, len(packet), packet[9] if packet[0] >> 4 == 4 else packet[6]))
        if packet[0] >> 4 == 4 and len(packet) >= 28:
            offset = (packet[0] & 15) * 4
            if (packet[9] == 1 and packet[offset] == 0 and pending and
                packet[offset+8:] == ('ARKOVPN:' + pending).encode() and
                packet[12:16] == socket.inet_aton('10.247.0.2') and checksum(packet[offset:]) == 0):
                acknowledge(pending, 4)
        reply = response(packet)
        if reply: peer.send(reply)
