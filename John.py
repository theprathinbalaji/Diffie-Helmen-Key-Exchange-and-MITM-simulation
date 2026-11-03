import socket
from Party import JOHN, ALICE, BOB, EVE, send, receive

# Select a standard 2048-bit DH modulus and generator.
modulus = int('''
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF
FFFFFFFF
'''.replace(' ', '').replace('\n', ''), 16)
generator = 2

John = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
John.bind(JOHN)
print('[JOHN]: \t Waiting for Alice.')

# Receive Alice's mode, then register Bob.
people = {}
public = {}
mode = None
configured = False

while True:
    packet, address = receive(John)
    kind = packet.get('type')
    name = packet.get('name')

    if kind == 'HELLO' and name in ('ALICE', 'BOB', 'EVE'):
        if name == 'EVE' and mode not in ('c', 'd'):
            continue
        # Record a participant only once; registration retries stay silent.
        if name not in people:
            print('[JOHN]: \t {} reported.'.format(name.title()))
        people[name] = address
        if name == 'ALICE':
            mode = packet['mode']

        if mode and 'ALICE' in people and 'BOB' in people and not configured:
            for person in ('ALICE', 'BOB'):
                send(John, people[person], 'SETUP', mode=mode, p=str(modulus), g=generator)
            configured = True
            print('[JOHN]: \t Mode {} and DH parameters distributed.'.format(mode))

        # Repeat setup replies if an earlier UDP reply was missed.
        if configured:
            send(John, address, 'SETUP', mode=mode, p=str(modulus), g=generator)

    if kind == 'PUB' and name in ('ALICE', 'BOB'):
        if name not in public:
            public[name] = {'public': packet['public'], 'signature': packet['signature'],
                            'verifying': packet['verifying']}
            print("[JOHN]: \t {}'s public key received.".format(name.title()))
        send(John, address, 'PUB_ACK')

    if len(public) == 2 and (mode not in ('c', 'd') or 'EVE' in people):
        for name, address in people.items():
            send(John, address, 'KEYS', mode=mode, ALICE=public['ALICE'], BOB=public['BOB'])
        print('[JOHN]: \t Keys announced. Goodbye.')
        break

John.close()
