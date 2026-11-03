import socket, secrets, select, sys, json
from Party import EVE, ALICE, BOB, register, receive, send
from cryptography.hazmat.primitives.asymmetric import dh, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Register with John and learn Alice's and Bob's public keys.
Eve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
Eve.bind(EVE)
setup = register(Eve, 'EVE')
mode = setup['mode']

while True:
    packet, _ = receive(Eve)
    if packet.get('type') == 'KEYS':
        break

# Prepare separate DH secrets for Alice and Bob.
numbers = dh.DHParameterNumbers(int(setup['p']), int(setup['g']))
private_alice = numbers.parameters().generate_private_key()
private_bob = numbers.parameters().generate_private_key()
keys = {}
for who, private in (('ALICE', private_alice), ('BOB', private_bob)):
    peer = dh.DHPublicNumbers(int(packet[who]['public']), numbers).public_key()
    secret = private.exchange(peer)
    keys[who] = HKDF(algorithm=hashes.SHA256(), length=32,
                     salt=None, info=b'project-chat').derive(secret)

fake_signer = ed25519.Ed25519PrivateKey.generate()
print('[EVE]: \t Waiting for Alice.')

# Impersonate Alice to Bob, and Bob to Alice.
while True:
    request, _ = receive(Eve)
    if request.get('type') == 'REQ':
        send(Eve, BOB, 'REQ', sender='ALICE')
        break

while True:
    response, _ = receive(Eve)
    if response.get('type') == 'RESP':
        send(Eve, ALICE, 'RESP', accepted=response['accepted'])
        if not response['accepted']:
            print('[EVE]: \t Bob declined.')
            Eve.close()
            exit()
        break

offers = {}
for person, address, private, disguise in (
    ('ALICE', ALICE, private_alice, 'BOB'),
    ('BOB', BOB, private_bob, 'ALICE')
):
    public = str(private.public_key().public_numbers().y)
    forged_signature = fake_signer.sign('{}|{}'.format(disguise, public).encode()).hex()
    offers[person] = {'public': public, 'signature': forged_signature}
    send(Eve, address, 'OFFER', **offers[person])

# Wait for both parties to accept or detect the substituted keys.
ready = set()
while len(ready) < 2:
    message, _ = receive(Eve)
    if message.get('type') == 'REQ':
        # Alice may still be waiting for Bob's acceptance.
        send(Eve, ALICE, 'RESP', accepted=True)
        send(Eve, ALICE, 'OFFER', **offers['ALICE'])
        continue
    if message.get('type') == 'READY':
        ready.add(message['name'])
        if message.get('detected'):
            print('[EVE]: \t My {} disguise was rejected.'.format(
                'BOB' if message['name'] == 'ALICE' else 'ALICE'))

print('[EVE]: \t Relay active. Commands: f=forward, n <message>=replace, t=tamper ciphertext, g=tamper GCM tag, -1=end.')

# Read intercepted packets and optionally replace their contents.
while True:
    ready, _, _ = select.select([Eve, sys.stdin], [], [])

    if sys.stdin in ready:
        command = sys.stdin.readline().strip()
        if command == '-1':
            send(Eve, ALICE, 'END', who='EVE')
            send(Eve, BOB, 'END', who='EVE')
            print('[EVE]: \t Chat ended.')
            break

    if Eve not in ready:
        continue

    packet, source = receive(Eve)
    if packet.get('type') == 'END':
        send(Eve, ALICE if source == BOB else BOB, 'END', who=packet.get('who', 'EVE'))
        print('[EVE]: \t Chat ended.')
        break

    if packet.get('type') != 'CHAT':
        continue

    who = 'ALICE' if source == ALICE else 'BOB'
    target = 'BOB' if who == 'ALICE' else 'ALICE'
    address = BOB if who == 'ALICE' else ALICE

    if mode == 'c':
        try:
            text = AESGCM(keys[who]).decrypt(bytes.fromhex(packet['nonce']),
                      bytes.fromhex(packet['payload']), who.encode()).decode()
        except Exception:
            continue
        print('[{}]:{}{}'.format(who, '\t\t ' if who == 'BOB' else '\t ', text))
    else:
        print('[{}]:{}{}'.format(who, '\t\t ' if who == 'BOB' else '\t ', packet.get('payload', '')))

    action = input('[EVE({})]: \t f / n <message> / t / g: '.format(who)).strip()
    if action == '-1':
        send(Eve, ALICE, 'END', who='EVE')
        send(Eve, BOB, 'END', who='EVE')
        break

    if mode == 'c':
        if action.startswith('n '):
            text = action[2:]
        nonce = secrets.token_bytes(12)
        ciphertext = bytearray(AESGCM(keys[target]).encrypt(nonce, text.encode(), who.encode()))

        # TEST CASE 4: flip a ciphertext byte; AES-GCM must reject the packet.
        if action == 't':
            ciphertext[0] ^= 0x01
            print('[EVE]: Ciphertext byte modified before forwarding.')
        # TEST CASE 6: flip the final authentication-tag byte.
        elif action == 'g':
            ciphertext[-1] ^= 0x01
            print('[EVE]: AES-GCM authentication-tag byte modified before forwarding.')

        send(Eve, address, 'CHAT', sender=who, wire_sender='EVE({})'.format(who),
             nonce=nonce.hex(), payload=bytes(ciphertext).hex())
    else:
        if action.startswith('n '):
            nonce = secrets.token_bytes(12)
            payload = secrets.token_bytes(len(action[2:].encode()) + 16)
            forged = fake_signer.sign(who.encode() + nonce + payload).hex()
            send(Eve, address, 'CHAT', sender=who, wire_sender='EVE({})'.format(who),
                 nonce=nonce.hex(), payload=payload.hex(), signature=forged)
        # Deliver the original valid packet so the chat can continue.
        packet['wire_sender'] = 'EVE({})'.format(who)
        Eve.sendto(json.dumps(packet).encode(), address)

Eve.close()
