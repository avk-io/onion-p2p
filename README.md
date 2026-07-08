# onion-p2p

yet another onion router, except this one's mine and I actually know why
every line of it exists.

built this from scratch to actually learn networking + crypto instead of
just importing a library and calling it a day. relay server, packet format,
encryption, multi-hop routing, the terminal UI — all designed and coded
from first principles, bugs and all.

> **status:** core protocol works and has been tested end to end (3-hop
> onion routing, relay-based peer discovery, actual adversarial testing —
> found a real crash bug and fixed it). there's a working ncurses TUI for
> direct encrypted chat. onion routing isn't wired into the chat UI yet.
> see [what's left](#whats-left) below.

## the idea

A wants to send B a message without any single middleman knowing both "who
sent it" and "who got it."

- A grabs a list of known peers from a relay server, picks 3 at random:
  P1, P2, P3.
- A wraps the message in 4 layers of encryption like an onion — outer layer
  addressed to P1, and each layer only reveals the *next* hop's identity,
  never the final destination or who originally sent it.
- Message goes P1 → P2 → P3 → B. Each hop decrypts only its own layer,
  learns only the next hop, forwards the still-sealed rest.
- B decrypts the last layer, gets the plaintext + sender's hashid (just an
  identity, no IP/port, so B can't even DM A directly without doing the
  whole dance again).

nobody except P1 (A's direct neighbor) and P3 (B's direct neighbor) ever
sees a real IP belonging to A or B. 
## how it's laid out

```
┌──────────────┐        ┌──────────────────────────────┐
│ Relay Server │◄──────►│  peers (register + discover)  │
│ (dumb directory,       └──────────────────────────────┘
│  hashid-checked)
└──────────────┘
        ▲
        │ LIST / REGISTER
        │
┌───────┴────────────────────────────────────────────────┐
│                                                           │
│   A ──seal(P1)──► P1 ──seal(P2)──► P2 ──seal(P3)──► P3   │
│                                                    │      │
│                                                    ▼      │
│                                                    B       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### what's what

| file | does |
|---|---|
| `relay_server.cpp` | concurrent TCP server, stores `{ip, port, pubkey, hashid}` per peer. handles `REGISTER` / `LIST`. doesn't know anything about onions, it's just a dumb validated directory. |
| `peer.hpp` | shared `Peer` struct, nothing fancy |
| `peer_client.cpp` | registers w/ relay, fetches the list, re-checks every entry's hashid against its pubkey (so a shady relay can't just swap in a fake pubkey) |
| `crypto_test.cpp` | proves `crypto_box_easy` round-trips and actually catches tampering |
| `onion_test.cpp` | no-network sim of the full seal/peel logic — figured out the whole layering scheme here before touching real sockets |
| `onion_relay.cpp` | generic middle-hop. same binary plays P1, P2, or P3 depending on args. loads/gens a persistent key, registers w/ relay, peels its layer, looks up next hop by hashid via the relay, forwards the rest |
| `onion_a.cpp` / `onion_b.cpp` | reference sender/recipient for the 3-hop chain |
| `onion_chat.cpp` | direct (non-onion) encrypted 2-way chat w/ live ncurses UI — background thread catches incoming msgs, Enter sends, peer list + relay info panels update live |
| `echo_server.cpp` / `echo_client.cpp` | og training-wheels files from figuring out asio sockets, kept around for the nostalgia |

## crypto, briefly

- every peer's got a persistent Curve25519 keypair (`crypto_box_keypair`), saved to disk so identity survives restarts
- hashid = `crypto_generichash` (BLAKE2b) of the pubkey — a stable public handle without leaking the full key upfront
- **relay tampering check**: every peer independently rehashes every pubkey it gets from the relay and checks it against the claimed hashid. malicious relay swapping in a fake key = instantly caught, since faking a hash collision isn't happening
- **onion layers use `crypto_box_seal`**, not the identity-bound `crypto_box_easy` — sealed boxes make a disposable keypair internally per-message and toss it, so no hop ever needs (or can get) the real sender's identity out of the crypto itself
- everything sent hop-to-hop is length-prefixed (4-byte length, then payload) since ciphertext is binary garbage and can't be split on a newline like a sane person's text protocol


## building it

need:
- [asio](https://think-async.com/Asio/) (standalone headers, no boost needed)
- [libsodium](https://doc.libsodium.org/)
- [ncurses](https://invisible-island.net/ncurses/) (for the TUI stuff)
- cmake ≥ 3.20

```bash
mkdir build && cd build
cmake ..
make
```

every `.cpp` has its own target in `CMakeLists.txt`.

## running the full chain locally

5 terminals, in order:

```bash
# relay
./relay_server

# recipient
./onion_b 127.0.0.1 12345

# middle hops, same binary 3 times
./onion_relay 7175 p3.key 127.0.0.1 12345   # P3
./onion_relay 7150 p2.key 127.0.0.1 12345   # P2
./onion_relay 7100 p1.key 127.0.0.1 12345   # P1

# send something
./onion_a
```

each `onion_relay` registers itself w/ the relay on boot and figures out its
next hop live by querying the relay with the hashid it just decrypted —
nothing hardcoded at runtime.

## running the chat TUI

```bash
./onion_chat <relay_ip> <relay_port> <own_port> <recipient_hashid>
```

run 2 instances (separate folders so the key files don't collide) pointed
at each other's hashid. `Ctrl+X` to quit without nuking your terminal.

## adversarial testing 

went back and tried to break my own design:

1. **malicious relay** — manually registered a fake peer w/ a pubkey/hashid
   that don't match. every peer fetching the list correctly flagged it,
   no special-casing needed, validation just worked.
2. **dead middle peer** — killed a middle hop mid-chain, sent another msg
   through the same route. **this actually crashed the upstream hop** —
   unhandled exception on a refused connection, real bug, found it by
   testing not by guessing. fixed by wrapping the forward step in a
   try/catch — now a dead hop just drops that one message and the relay
   node stays alive for everything else.

## who learns what (the whole point of this project)

| party | learns |
|---|---|
| P1 | A's IP/port (direct conn), P2's hashid |
| P2 | P1's hashid, P3's hashid |
| P3 | P2's hashid, B's hashid |
| B  | P3's IP/port (direct conn), A's hashid only — no IP/port |

no single non-endpoint hop ever knows both ends. same residual risk as
tor or any onion design — first+last hop compromised together + timing
correlation is the only real crack, not a crypto weakness.

## what's left

- **onion routing isn't in `onion_chat` yet** — the live TUI does direct
  P2P only (`crypto_box_seal`, one hop). merging the two chains is mostly
  plumbing at this point, just haven't done it.
- **NAT / real deployment** — everything above is `127.0.0.1` only. real
  users are behind NAT and can't accept random inbound connections, which
  the whole design currently assumes every hop can do. probably fixed via
  an HTTPS/mailbox-polling model instead of raw listening sockets, or by
  routing through actual Tor instead of a homemade relay set.
- **operator trust** — if one person (me) runs all 3 relay hops like in
  this local setup, that person can correlate sender/recipient by timing
  regardless of how good the encryption is. real "even the operator can't
  trace it" needs independent third parties running the hops — which is
  basically just... tor. if that property actually matters for a real
  deployment, routing through tor instead of growing my own relay network
  is the smarter move.
- **TUI polish** — no TAB panel switching, no live peer-list refresh yet.

## why

- wanted a way for people to talk anonymously , mainly protecting identity from outsiders/eavesdropperd/attackers watching the network, but the design also hides your identity from the person you're talking to, which sounds like a bad design at first (Why would you want to hide from your own conversation partner ?).

turns out that's kind of the point, not a flaw. B only learns A's hashid,never an IP, so B can reply knowing its the same A across the messages, but can't independently track A or dox him/her. even if B turns out to be shady or gets nosy later , the same protection that keeps a network observer(attacker) in grey also keeps the other side(B) of conversation form becoming a threat vector. you're trusting the content of what someone says without being forced to also hand them the means to track you down over it