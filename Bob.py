import socket
from Party import BOB, ALICE, EVE, register, exchange, send, receive, check_offer, chat

# Register with John and exchange DH public keys.
Bob = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
Bob.bind(BOB)
setup = register(Bob, 'BOB')
mode = setup['mode']
print('[JOHN]: \t Mode {}. Generator {} received.'.format(mode, setup['g']))

private, key, identity, trusted = exchange(Bob, 'BOB', setup)
print('[JOHN]: \t Alice is ready. John has departed.')

# Ask Bob's consent when Alice requests a conversation.
while True:
    packet, address = receive(Bob)
    if packet.get('type') == 'REQ':
        break

reply = input('[BOB]:\t\t Talk to Alice? (Y/N): ').strip().lower()
while reply not in ('y', 'n'):
    reply = input('[BOB]:\t\t Y/N: ').strip().lower()

send(Bob, address, 'RESP', accepted=(reply == 'y'))
if reply == 'n':
    Bob.close()
    exit()

# Check Eve's proposed key; retain John's trusted key if it fails.
if mode in ('c', 'd'):
    while True:
        packet, _ = receive(Bob)
        if packet.get('type') == 'OFFER':
            key = check_offer(packet, mode, key, private, setup, trusted, 'ALICE')
            send(Bob, EVE, 'READY', name='BOB', detected=(mode == 'd'))
            break

chat(Bob, 'BOB', mode, key, identity, trusted, address if mode in ('a', 'b') else EVE)
Bob.close()
