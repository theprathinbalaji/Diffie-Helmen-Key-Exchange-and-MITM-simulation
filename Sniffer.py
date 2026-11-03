import socket, json, struct

# Capture only chat payloads on the local UDP interface.
sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sniffer.bind(('lo', 0))

try:
    while True:
        frame, address = sniffer.recvfrom(65535)
        if address[2] == socket.PACKET_OUTGOING or frame[12:14] != b'\x08\x00':
            continue

        ip = 14
        if frame[ip + 9] != 17:
            continue

        udp = ip + (frame[ip] & 15) * 4
        source, dest, length, _ = struct.unpack('!HHHH', frame[udp:udp + 8])
        if source not in (4001, 4002, 4003) or dest not in (4001, 4002, 4003):
            continue

        try:
            packet = json.loads(frame[udp + 8:udp + length].decode())
        except (ValueError, UnicodeError):
            continue

        if packet.get('type') == 'CHAT':
            who = packet.get('wire_sender', '?')
            print('[{}]:{}{}'.format(who, '\t\t ' if who == 'BOB' else '\t ',
                                    packet.get('text', packet.get('payload', ''))), flush=True)
except KeyboardInterrupt:
    pass
finally:
    sniffer.close()
