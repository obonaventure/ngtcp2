# Minimal Multicast QUIC implementation notes

Tracking implementation of https://github.com/louisna/minimal-multicast-quic-ietf-126
in ngtcp2, client-side, done incrementally.

**Specification**: https://github.com/louisna/minimal-multicast-quic-ietf-126

## Step 1 (done): `multicast_support` transport parameter

Added the experimental `multicast_support` transport parameter (codepoint `0xff4d40`,
empty/flag value) so the client can advertise support and interop can be checked at
the wire level. Mirrors the existing `grease_quic_bit` pattern in:
- `lib/ngtcp2_transport_params.h` (codepoint define)
- `lib/includes/ngtcp2/ngtcp2.h` (`multicast_support` field on `ngtcp2_transport_params`)
- `lib/ngtcp2_transport_params.c` (encode/decode)
- `lib/ngtcp2_qlog.c` / `lib/ngtcp2_log.c` (qlog/verbose-log exposure)
- `examples/client.cc` (`params.multicast_support = 1`)

Verified: library + full `tests/main` suite build and pass (266/266) after updating
the two hard-coded log/qlog fixture tests that needed the new field appended
(`tests/ngtcp2_log_test.c`, `tests/ngtcp2_qlog_test.c`). Example `osslclient` binary
also built successfully (see build notes below).

## Step 2 (done): MC_FLOW frame

### Wire format (from the draft)

```
Type (varint) = 0xff4d43
Flow ID Length (8 bits, 1-20)
Flow ID (Flow ID Length bytes)
IP Version (8 bits: 4 or 6)
Source IP (4 or 16 bytes, network byte order, per IP Version)
Group IP (4 or 16 bytes, network byte order, per IP Version)
UDP Port (16 bits)
Cipher Suite (16 bits, e.g. 0x1301 = TLS_AES_128_GCM_SHA256)
First Packet Number (varint)
Secret Length (varint)
Secret (Secret Length bytes, typically 32)
```

Multicast packets: standard QUIC 1-RTT short header, DCID = Flow ID, Key Phase 0,
payload contains only DATAGRAM (+ optional PADDING/PING) frames. Keys via unmodified
RFC 9001 HKDF-Expand-Label ("quic key"/"quic iv"/"quic hp") over the shared Secret.
(The draft text claims packet number length is always fixed at 4 bytes; the real
server tested against does not honor that — see "Real-server interop findings"
below. Treat packet number length as standard variable-length QUIC encoding.)

### Part A — Library: MC_FLOW frame decode (lib/)

MC_FLOW (type `0xff4d43`) is the **first >1-byte-varint frame type** ngtcp2
supports — every prior frame type fit in one byte, and `ngtcp2_frame_decoder_decode`
had a literal TODO comment for exactly this gap (lib/ngtcp2_pkt.c). Implemented by
mirroring existing patterns exactly:

1. **`lib/ngtcp2_pkt.h`**: `NGTCP2_FRAME_MC_FLOW` codepoint define; `ngtcp2_mc_flow`
   struct (pointer+length for the two variable-length byte strings Flow ID/Secret,
   matching the `ngtcp2_new_token` pattern — no copy needed since the underlying UDP
   packet buffer outlives the decode call); added to the `ngtcp2_frame` union;
   `ngtcp2_pkt_decode_mc_flow_frame` declaration.
2. **`lib/ngtcp2_pkt.c`**: `ngtcp2_frame_decoder_decode` now reads the frame type as
   a `uint64_t` varint (`ngtcp2_get_uvarintlen`/`ngtcp2_get_uvarint`) instead of a
   single byte, dispatching to the new decode function; `ngtcp2_pkt_decode_mc_flow_frame`
   implemented as a single forward pass with bounds checks at each field, modeled on
   `ngtcp2_pkt_decode_new_connection_id_frame`/`ngtcp2_pkt_decode_new_token_frame`.
3. **`lib/includes/ngtcp2/ngtcp2.h`**: `ngtcp2_recv_mc_flow` callback typedef and
   `recv_mc_flow` field on `ngtcp2_callbacks`, mirroring `recv_datagram` — this is how
   the parsed frame reaches the application.
4. **`lib/ngtcp2_conn.c`**: `conn_call_recv_mc_flow`/`conn_recv_mc_flow` mirroring the
   datagram equivalents, dispatched from the main 1-RTT frame switch.
5. **`lib/ngtcp2_log.c`** / **`lib/ngtcp2_qlog.c`**: frame-name cases added — both
   switches have a `default: ngtcp2_unreachable();` trap, so this was required for
   correctness, not just cosmetic.
6. **`tests/ngtcp2_pkt_test.c`**: `test_ngtcp2_pkt_decode_mc_flow_frame` — hand-built
   IPv4/IPv6 byte buffers (no library-side encoder was added, per scope decision),
   decode assertions, plus a truncation-fuzz loop asserting `NGTCP2_ERR_FRAME_ENCODING`
   for every truncated length.

Verified: library + full `tests/main` suite build and pass (267/267).

### Part B — Example client: multicast join + standalone decrypt (examples/)

No existing multicast code in the repo, and no existing "decrypt a standalone
short-header packet outside `ngtcp2_conn`" API — this is new code in the example
client using only public crypto/pkt helpers, since MC_FLOW packets use the Flow ID
as DCID and have nothing to do with the main connection's key schedule.

1. **`examples/client.h`/`client.cc`**: `McFlowState` struct holds flow id, src/group
   IP, port, cipher suite, secret, and derived key/iv/hp_key. `Client::on_recv_mc_flow`
   (wired via the `recv_mc_flow` callback) stores the flow state, derives keys, and
   joins the multicast group.
2. **Multicast join** (`create_mc_sock`): opens a UDP socket bound to the announced
   port and joins the (S,G) group. See "Real-server interop findings" below for two
   join-correctness bugs found and fixed.
3. **Key derivation**: HKDF-Expand-Label implemented locally via HMAC-SHA256 (not
   ngtcp2's internal `ngtcp2_crypto_derive_packet_protection_key`, since that lives in
   the non-public `crypto/shared.h`, off the examples' include path). Only cipher
   suite `0x1301` (TLS_AES_128_GCM_SHA256) is supported; others are logged and
   ignored.
4. **Standalone packet unprotect + decrypt** (`Client::process_mc_packet`): uses
   public `ngtcp2_pkt_decode_hd_short` to parse up to the (still-protected) packet
   number field, computes the RFC 9001 §5.4.2 HP sample (fixed at `pn_offset + 4`
   regardless of actual encoded PN length), unmasks the first byte, reads the *real*
   packet-number length from its low 2 bits (see "Real-server interop findings" — the
   draft's claimed fixed 4-byte PN doesn't hold against the real server), forms the
   AEAD nonce, and decrypts via raw OpenSSL EVP (AES-128-GCM) with AAD = the
   reconstructed unprotected header.
5. **DATAGRAM extraction** (`Client::extract_mc_datagrams`): hand-rolled minimal
   frame-type loop (PADDING/PING/DATAGRAM/DATAGRAM_LEN only) over the decrypted
   payload, rather than reaching into the internal `ngtcp2_pkt_decode_datagram_frame`
   (examples only have `lib/includes` on their include path, not internal `lib/*.h`).
   Extracted datagrams are currently only printed, not handed to a real application
   callback.

Only one multicast flow per connection is joined (matches the draft's single-flow
scope); a second MC_FLOW frame is ignored while one is active. No ACK generation, no
idle-timer interaction — this path never touches `conn_`, so that's automatic.

Debug logging (gated on `!config.quiet`) was added throughout this path — every
multicast socket recv, the exact reason for any decode/HP-mask/decrypt rejection,
full join-state (fd, flow_id, src/group IP, port, cipher suite, derived
secret/key/iv/hp_key) at join time, and pkt_num/header/nonce/tag on decrypt failure
— needed because the client would otherwise fail silently at any stage, making "no
traffic" and "traffic rejected somewhere" indistinguishable from the logs. This
logging is what made the real-server debugging below tractable.

## Step 3 (done): `mc-quic` ALPN

Added a `--mc-quic` client CLI flag (`examples/client.cc`) that, when set, makes the
client send ALPN token `"mc-quic"` (`MC_ALPN` in `examples/shared.h`) instead of the
usual `h3`/`hq-interop`, matching the draft's interop requirement
(`ALPN: "mc-quic"`). Wired into the client TLS session setup for the ossl, quictls,
boringssl, and wolfssl backends (`tls_client_session_*.cc`) by checking
`config.mc_quic` before the existing `AppProtocol` H3/HQ switch. The picotls backend
was intentionally left untouched — its ALPN list uses a different
`negotiated_protocols` array-of-structs representation that would need its own
verified change, and picotls isn't buildable/testable in this environment.

Usage: `osslclient --mc-quic <host> <port>`.

## Real-server interop findings (2026-07-18/19)

Live testing against a real hackathon server surfaced three independent bugs beyond
what unit tests could catch, fixed in order:

**1. ALPN/transport-param/frame parsing all worked on the first try.** First live run
against `192.168.1.196:4434` confirmed ALPN negotiated as `mc-quic`,
`multicast_support` TP round-tripped, and MC_FLOW was parsed correctly
(`flow_idlen=20 ip_version=4 udp_port=4436 cipher_suite=0x1301 secretlen=32`). No
multicast packets arrived, though.

**2. Multicast join bound to the wrong interface.** `create_mc_sock` joined the SSM
group with `imr_interface = INADDR_ANY` (IPv4). On a multi-homed test machine (two
addresses on one interface, one behind a default route to a different subnet), an
unqualified interface hint can make the kernel send the IGMPv3 join report out the
wrong interface — the switch/AP never adds the host to the group, and no multicast
traffic is ever delivered, even though socket()/bind()/setsockopt() all succeed
without error. **Fix**: `create_mc_sock` now takes the client's actual local address
(read via `ngtcp2_conn_get_path2(conn_)` → `Endpoint::addr`, the same address the
unicast connection is using) and uses it as `imr_interface`, instead of
`INADDR_ANY`.

**3. Server announced any-source multicast (ASM), not SSM.** After the interface fix,
still nothing arrived — but the enhanced join-state debug line revealed the server's
MC_FLOW frame carried **Source IP = `0.0.0.0`** (`src=0.0.0.0 group=226.1.1.1`),
i.e. an ASM group, despite the draft's wire format nominally always including a
Source IP field. `create_mc_sock` unconditionally did a source-specific join
(`IP_ADD_SOURCE_MEMBERSHIP`/`MCAST_JOIN_SOURCE_GROUP`) filtering on that exact source
address — a filter of `0.0.0.0` matches no real sender, so every packet was silently
dropped by the kernel. **Fix**: `create_mc_sock` now detects an all-zero/unspecified
source address (4 bytes IPv4 / 16 bytes IPv6) and falls back to a plain any-source
join (`IP_ADD_MEMBERSHIP`/`MCAST_JOIN_GROUP`).

**4. Packet number length isn't actually fixed at 4 bytes.** After fix #3, packets
arrived (`mc recvfrom: N bytes`) but every one failed AEAD tag verification
(`mc_flow: packet decrypt failed`). The failure-line header dump showed the unmasked
first byte's packet-number-length bits decoding to 3 bytes, not the 4 our code
hardcoded (per the draft's claim of a fixed 4-byte PN) — one stray byte was being
consumed as "packet number" that was actually the first ciphertext byte, corrupting
the AEAD nonce and misaligning the payload/AAD boundary, so the tag could never
verify. **Fix**: `Client::process_mc_packet` now unmasks only the first byte first,
reads the real packet-number length from its low 2 bits (standard QUIC short-header
decoding), and only then unmasks/reads that many packet-number bytes. The HP sample
offset itself is unaffected by this (RFC 9001 §5.4.2 fixes that at `pn_offset + 4`
regardless of the real encoded PN length).

**Confirmed working end-to-end after fix #4**: MC_FLOW frame parsed, group joined on
the correct interface with the correct join mode, packets received, and decrypted
successfully, with extracted DATAGRAM payloads printed.

A standalone HKDF-Expand-Label comparison test (our HMAC-SHA256 implementation vs.
OpenSSL's own `EVP_KDF`-based HKDF-expand, same secret/info/length) was written
during this investigation to rule out a key-derivation bug before the real packet-
number-length root cause was found; kept in
`/private/tmp/.../scratchpad/hkdf_test2.cc` for reference, not part of the repo.

## Build environment notes

- `tests/munit` and `third-party/urlparse` are git submodules that must be
  initialized: `git submodule update --init`.
- Building the example clients/servers requires `libev` and `libnghttp3` in addition
  to a TLS backend (OpenSSL here) — cmake produces per-backend binaries named
  `osslclient`/`osslserver` (not plain `client`/`server`).
- Homebrew's `libnghttp3` (1.17.0 stable) is missing symbols this checkout's HTTP/3
  example code expects (`nghttp3_conn_close_stream2`,
  `NGHTTP3_STREAM_CLOSE_FLAG_*`). Built nghttp3 from git HEAD (1.17.90) into a local
  prefix instead, and ran `brew unlink libnghttp3` so its headers stop shadowing the
  local build via `-I/opt/homebrew/include`. Point cmake at the local build via
  `PKG_CONFIG_PATH=<local-prefix>/lib/pkgconfig cmake ..`.
  Remember to `brew link libnghttp3` back if the Homebrew version is needed elsewhere
  on this machine.
