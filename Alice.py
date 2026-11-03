import socket
from Party import ALICE, BOB, EVE, register, exchange, send, receive, check_offer, chat

# Choose the mode and report to John.
mode = input('Mode (a/b/c/d): ').strip().lower()
while mode not in ('a', 'b', 'c', 'd'):
    mode = input('Mode (a/b/c/d): ').strip().lower()

Alice = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
Alice.bind(ALICE)
setup = register(Alice, 'ALICE', mode)
print('[JOHN]: \t Mode {}. Generator {} received.'.format(mode, setup['g']))

# Exchange DH public keys through John.
private, key, identity, trusted = exchange(Alice, 'ALICE', setup)
print('[JOHN]: \t Bob is ready. John has departed.')

# Request Bob; Eve intercepts the request only in attack modes.
address = EVE if mode in ('c', 'd') else BOB
print('[ALICE]: \t Requested a chat with Bob.')

# Repeat the request until Bob's decision reaches Alice.
Alice.settimeout(1)
while True:
    send(Alice, address, 'REQ', sender='ALICE')
    try:
        packet, _ = receive(Alice)
    except socket.timeout:
        continue
    if packet.get('type') == 'RESP':
        if not packet.get('accepted'):
            print('[ALICE]: \t Bob declined.')
            Alice.close()
            exit()
        break
Alice.settimeout(None)

# Accept or reject the substituted DH value.
if mode in ('c', 'd'):
    while True:
        packet, _ = receive(Alice)
        if packet.get('type') == 'OFFER':
            key = check_offer(packet, mode, key, private, setup, trusted, 'BOB')
            send(Alice, EVE, 'READY', name='ALICE', detected=(mode == 'd'))
            break

chat(Alice, 'ALICE', mode, key, identity, trusted, address)
Alice.close()
