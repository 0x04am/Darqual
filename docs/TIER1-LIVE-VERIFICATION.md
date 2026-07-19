# Tier-1 Dead-Drop MVP — Live Verification

Date: 2026-07-19
Branch: `feat/tier1-dead-drop-mvp`
Hosts: relay on **avante**, sender/receiver on **jade**
Transport: live Tor v3 onion service (Arti), no clearnet listener

## Scenario

1. Avante launched `darqual-tor-node relay` with PoW difficulty 8 and persisted state.
2. Alice on jade ran `drop-send` to the relay onion, addressed to Bob's contact card.
3. Alice's process exited.
4. Bob, who had not been online while Alice sent, ran `drop-fetch` against the relay and decrypted the message.
5. Eve fetched the same public relay block and decrypted zero messages.
6. The relay was stopped and restarted with the same state file and stable onion identity.
7. Bob fetched and decrypted the retained message again after relay restart.

## Sanitized transcript

```text
[relay] onion service: <stable-relay>.onion
[relay] state: /tmp/dq-tier1-relay/ledger.bin
[relay] Tier-1 single relay — NOT global-observer resistant

[drop-sent] relay=<stable-relay>.onion epoch=29740864 entries=1

# Bob after Alice exited
[drop-recv] tier1 offline hello from jade
[drop-fetch] relay=<stable-relay>.onion blocks=1 messages=1

# Eve, same public ledger
[drop-fetch] relay=<stable-relay>.onion blocks=1 messages=0

# relay restart, then Bob again
[drop-recv] tier1 offline hello from jade
[drop-fetch] relay=<stable-relay>.onion blocks=1 messages=1
```

## Claims this verifies

- Sender and recipient do not dial one another in dead-drop mode; each dials only the relay onion.
- Store-and-forward works while the recipient is offline.
- Relay persistence survives process restart.
- Public block retrieval does not let a wrong recipient decrypt Bob's lockbox.
- The relay stores ciphertext and labels, not plaintext.

## Claims this does NOT verify

- Global-observer contact-graph privacy (a single relay still exposes timing and access patterns).
- Private writes or reads (no DPF/PIR).
- Multi-relay anytrust committees.
- Deduplicated delivery/read receipts.
- Forward-secret persisted keywheel labels.
- External audit or production safety.
