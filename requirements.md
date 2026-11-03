Install: python3 -m pip install cryptography

Open separate terminals, in order:
1. sudo python3 Sniffer.py
2. python3 Alice.py         (choose a, b, c or d)
3. python3 John.py
4. python3 Bob.py
5. python3 Eve.py          (only in c and d)

Bob enters Y/N when asked; only Alice initiates the chat request.
Alice sends first; Bob replies after receiving. Enter -1 on your turn to end the chat (or Eve can end it at any time).
In modes c/d, Eve uses f, n <message>, or -1.
Stop Sniffer with Ctrl+C.

For simplicity, John selects the standard 2048-bit DH group, not a newly generated prime.
In mode d, John is the initial trusted source of Ed25519 verification keys.
The <<EVE DETECTED>> label indicates the known attack route; Ed25519 rejects forged signatures, not passive forwarding.
