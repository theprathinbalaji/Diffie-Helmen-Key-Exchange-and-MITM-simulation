import socket, json, secrets, select, sys, os
from cryptography.hazmat.primitives.asymmetric import dh, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

JOHN = ('127.0.0.1', 4000)
ALICE = ('127.0.0.1', 4001)
BOB = ('127.0.0.1', 4002)
EVE = ('127.0.0.1', 4003)


# Send a simple UDP message.
def send(sock, address, kind, **details):
    packet = {'type': kind, **details}
    sock.sendto(json.dumps(packet).encode(), address)


# Read a UDP message.
def receive(sock):
    data, address = sock.recvfrom(65535)
    try:
        return json.loads(data.decode()), address
    except (ValueError, UnicodeError):
        return {}, address


# Report to John and receive the selected mode and DH parameters.
def register(sock, name, mode=None):
    sock.settimeout(0.5)
    while True:
        send(sock, JOHN, 'HELLO', name=name, mode=mode)
        try:
            data, _ = receive(sock)
            if data.get('type') == 'SETUP':
                sock.settimeout(None)
                return data
        except socket.timeout:
            continue


# MODE A: Generate a DH pair and show matching HKDF keys without sending secrets.
def exchange(sock, name, setup):
    mode = setup['mode']
    numbers = dh.DHParameterNumbers(int(setup['p']), int(setup['g']))
    private = numbers.parameters().generate_private_key()
    public = private.public_key().public_numbers().y

    identity = ed25519.Ed25519PrivateKey.generate() if mode == 'd' else None
    signed_data = '{}|{}'.format(name, public).encode()
    signature = identity.sign(signed_data).hex() if identity else ''
    verifying = identity.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex() if identity else ''

    sock.settimeout(0.5)
    while True:
        send(sock, JOHN, 'PUB', name=name, public=str(public), signature=signature, verifying=verifying)
        try:
            data, _ = receive(sock)
            if data.get('type') == 'PUB_ACK':
                break
        except socket.timeout:
            continue
    sock.settimeout(None)

    # Wait for John to announce both public keys.
    while True:
        data, _ = receive(sock)
        if data.get('type') == 'KEYS':
            break

    other = 'BOB' if name == 'ALICE' else 'ALICE'
    peer = dict(data[other])

    # TEST CASE 5: optional test hook to feed an invalid DH public value.
    # Enable on BOTH Alice and Bob with TEST_INVALID_DH=1 for a clean test run.
    if os.environ.get('TEST_INVALID_DH') == '1':
        peer['public'] = '1'
        print('[TEST 5] Injecting invalid DH public value y=1 for validation.')

    if mode == 'd':
        trusted = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(peer['verifying']))
        trusted.verify(bytes.fromhex(peer['signature']), '{}|{}'.format(other, peer['public']).encode())
    else:
        trusted = None

    peer_y = int(peer['public'])
    if peer_y <= 1 or peer_y >= int(setup['p']) - 1:
        print('[TEST 5] Invalid Diffie-Hellman public value rejected: y must be in [2, p-2].')
        raise SystemExit(0)
    try:
        peer_key = dh.DHPublicNumbers(peer_y, numbers).public_key()
        secret = private.exchange(peer_key)
    except ValueError as error:
        print('[TEST 5] Invalid Diffie-Hellman public value rejected:', error)
        raise SystemExit(0)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'project-chat').derive(secret)
    print('[{}]:{}Keys verified.'.format(name, '\t\t ' if name == 'BOB' else '\t '))
    return private, key, identity, trusted


# MODE B: Encrypt outgoing messages with AES-GCM.
def send_chat(sock, address, name, mode, key, identity, text):
    if mode == 'a':
        send(sock, address, 'CHAT', sender=name, wire_sender=name, text=text)
        return

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode(), name.encode())
    signature = identity.sign(name.encode() + nonce + ciphertext).hex() if mode == 'd' else ''
    send(sock, address, 'CHAT', sender=name, wire_sender=name,
         nonce=nonce.hex(), payload=ciphertext.hex(), signature=signature)


# MODE D: Check the suspected impostor's signature on the DH value.
def check_offer(packet, mode, key, private, setup, trusted, expected):
    if mode not in ('c', 'd'):
        return key

    valid = mode == 'c'
    if mode == 'd':
        try:
            trusted.verify(bytes.fromhex(packet['signature']),
                           '{}|{}'.format(expected, packet['public']).encode())
            valid = True
        except (InvalidSignature, ValueError, KeyError):
            print('<<EVE DETECTED>>')

    if valid:
        numbers = dh.DHParameterNumbers(int(setup['p']), int(setup['g']))
        other_key = dh.DHPublicNumbers(int(packet['public']), numbers).public_key()
        secret = private.exchange(other_key)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'project-chat').derive(secret)
    return key


# MODES A-D: Alice sends first; Bob replies only after receiving.
def chat(sock, name, mode, key, identity, trusted, address):
    other = 'BOB' if name == 'ALICE' else 'ALICE'
    turn = name == 'ALICE'
    print('[{}]:{}Chat started. Enter -1 to leave.'.format(name, '\t\t ' if name == 'BOB' else '\t '))

    while True:
        # Wait for either a reply or your own turn to type.
        if turn:
            print('[{}]:{}'.format(name, '\t\t ' if name == 'BOB' else '\t '), end='', flush=True)
            ready, _, _ = select.select([sock, sys.stdin], [], [])
            if sys.stdin in ready:
                line = sys.stdin.readline()
                text = line.rstrip('\n')
                if not line or text == '-1':
                    send(sock, address, 'END', who=name)
                    print('\n[{}]:{}Chat ended.'.format(name, '\t\t ' if name == 'BOB' else '\t '))
                    break
                if text:
                    send_chat(sock, address, name, mode, key, identity, text)
                    turn = False
                continue
        else:
            ready = [sock]

        if sock not in ready:
            continue

        packet, _ = receive(sock)
        if packet.get('type') == 'END':
            who = packet.get('who', other)
            ending = 'Eve, the middlewoman decided to end the chat.' if who == 'EVE' else '{} decided to end the chat.'.format(who.title())
            print('\n{}'.format(ending))
            break

        if packet.get('type') != 'CHAT' or turn:
            continue

        # Verify and display the received message before allowing a reply.
        if mode == 'a':
            text = packet.get('text', '')
        else:
            try:
                nonce = bytes.fromhex(packet['nonce'])
                ciphertext = bytes.fromhex(packet['payload'])
                if mode == 'd':
                    trusted.verify(bytes.fromhex(packet['signature']),
                                   other.encode() + nonce + ciphertext)
                text = AESGCM(key).decrypt(nonce, ciphertext, other.encode()).decode()
            except (InvalidSignature, InvalidTag, ValueError, KeyError, UnicodeError):
                if mode == 'c':
                    print('\n[{}]:{}<<AES-GCM AUTHENTICATION FAILED: MESSAGE REJECTED>>'.format(
                        name, '\t\t ' if name == 'BOB' else '\t '))
                    # In Mode C the tampered packet is the only packet forwarded;
                    # let the receiver take the next turn instead of deadlocking.
                    turn = True
                else:
                    print('\n[{}]:{}<<EVE DETECTED>>'.format(other, '\t\t ' if other == 'BOB' else '\t '))
                continue

        label = ' <<EVE DETECTED>>' if mode == 'd' else ''
        print('\n[{}]:{}{}{}'.format(other, '\t\t ' if other == 'BOB' else '\t ', text, label))
        turn = True