# TeamSpeak-3-Protokoll – Reverse-Engineering-Notizen

Untersuchte Artefakte (in `_extract/`):

| Artefakt | Inhalt |
|---|---|
| `teamspeak3-server_linux_amd64-3.13.8.tar.bz2` | `ts3server` (ELF x86-64, 13,7 MB), SQL-Skripte, `serverquerydocs/` |
| `teamspeak-client.msi` | **TeamSpeak-6-Client** (nicht der alte Qt-TS3-Client): `ExecFile` (Launcher), `libcef.dll` (Chromium 151), UI als JS-Bundle, nativer Protokoll-Core `filA1F7F64B7DA97CEEF8FDD6F10A2E8D56` (57 MB DLL) |

Ein Disassembler (Ghidra/IDA) war auf diesem Rechner nicht eingerichtet. Die Belege unten stammen deshalb aus Byte- und String-Suchen in den Binaries. Alles ohne direkten Beleg ist als **Annahme** markiert. Diese Annahmen folgen der öffentlichen Protokolldokumentation, z. B. ReSpeak/tsclientlib.

## Belege aus den Binaries

| Befund | Server `ts3server` | Client-Core `filA1F7…` |
|---|---|---|
| Init-MAC `TS3INIT1` | 5 Treffer, u. a. als `mov rax, imm64` @0xa0eed | 2 Treffer |
| Ed25519-Lizenz-Root-Key `cd0de2ae…3812408a` | @0x808020 | @0x2ef0a08 (+ Präfix als Immediate @0x223f409) |
| `clientinitiv`, `initivexpand2`, `clientek`, `initserver` | ja | ja |
| Legacy-`initivexpand` (ohne `2`) | nein | ja, getrennter String |
| `notifycliententerview`, `channellistfinished`, `sendtextmessage`, `clientmove`, … | ja | ja |
| `client_version_sign`, `client_key_offset`, `hwid` | – | ja |
| ServerQuery-Banner „Welcome to the TeamSpeak 3 ServerQuery interface …“ | ja (wörtlich übernommen) | – |

Fake-Key und Nonce stammen aus dem 32-Byte-String `c:\windows\system\firewall32.cpl` (ts3server @0x7b26c8): key = `c:\windows\syste`, nonce = `m\firewall32.cpl`. **Verifiziert**: Damit ließ sich ein live mitgeschnittenes `initivexpand2` des echten Servers entschlüsseln. Die oft zitierte Variante `…\firmwaredata` ist falsch.

Der Server spricht beide Handshake-Varianten. 3.13.8 kennt nur noch `initivexpand2` als String, der Client zusätzlich noch `initivexpand`. Deshalb nutzt der Rust-Server standardmäßig den Legacy-Handshake: Der funktioniert ohne offizielle Lizenz.

## Paketformat

```
C->S: MAC[8] | packet_id u16 | client_id u16 | type|flags u8   (13 Byte Header)
S->C: MAC[8] | packet_id u16 |                 type|flags u8   (11 Byte Header)
Typen:  0 Voice, 1 VoiceWhisper, 2 Command, 3 CommandLow, 4 Ping, 5 Pong, 6 Ack, 7 AckLow, 8 Init
Flags:  0x80 Unencrypted, 0x40 Compressed (QuickLZ), 0x20 NewProtocol (C->S Commands), 0x10 Fragmented
```

- Maximal 500 Byte pro Datagramm. Größere Commands werden fragmentiert. Das erste und das letzte Fragment tragen das Flag `Fragmented`. `Compressed` steht nur am ersten Fragment.
- Commands und CommandLow sind zuverlässig: Die Gegenseite bestätigt mit Ack/AckLow (Payload = `packet_id`). Sie werden in Reihenfolge ausgeliefert. Jeder Typ hat einen eigenen ID-Zähler mit Generation (Überlauf nach 65535).
- Verschlüsselung: AES-128-EAX mit 8-Byte-Tag (= MAC). Associated Data = Header ohne MAC.
- Pro-Paket-Schlüssel: `SHA256(dir(0x31 C->S / 0x30 S->C) | type | generation u32 | shared_iv)`. Daraus key = [0..16] und nonce = [16..32], dabei `key[0..2] ^= packet_id`.
- Ping/Pong sind unverschlüsselt. Als MAC dient `SHA1(shared_iv)[0..8]`.

## Verbindungsaufbau

1. **Init1** (Typ 8, MAC `TS3INIT1`, ID 101): fünf Schritte inklusive Zeit-Puzzle `y = x^(2^level) mod n`. Die Byte-Layouts stehen in `tsproto/src/init.rs`. Schritt 4 enthält `clientinitiv alpha omega ot=1 ip`.
2. **Legacy** – `initivexpand alpha beta omega`:
   - `shared_iv = SHA1(ECDH-P256-x) ^ (alpha‖beta)`, 20 Byte.
3. **Neu** – `initivexpand2 l beta omega ot proof tvd`:
   - Aus der Lizenzkette `l` folgt der Server-Key: `key_i = P_i·clamp(SHA512(block_i[1..])[0..32]) + key_{i-1}`, ausgehend vom Root-Key. Punkte werden **nicht** negiert eingelesen. Das wurde verifiziert: Von 16 Vorzeichen-/Hash-Varianten akzeptiert nur diese der echte Server. Blocktypen: 0 Intermediate, 2 Server (Typ u8, max_clients u32, Issuer), **32 Ephemeral** (beobachtet in 3.13.8, ohne Inhalt).
   - Der Client antwortet mit `clientek ek proof`. `proof` ist eine ECDSA-P256-Signatur über `ek‖beta`.
   - `shared_iv = SHA512(ek·server_key) ^ (alpha‖beta)`, 64 Byte.
4. `clientinit …` → `initserver aclid=…`. Danach sendet der echte Server (beobachtet) `channellist`, `notifycliententerview` (eigener Client mit `reasonid=2`), `channellistfinished`, `notifychannelgrouplist`, `notifyservergrouplist` und `notifyclientneededpermissions`.
   - Die erste C->S-Command-ID ist 1, denn `clientinitiv` zählt als 0. `clientek` geht noch mit dem Fake-Key raus, ab `clientinit` gilt der neue Schlüssel. Der Server bestätigt `clientek` mit dem Fake-Key.

Identität: P-256-Schlüssel, `omega` = DER im libtomcrypt-Format, UID = `base64(SHA1(omega))`. Das Security-Level entspricht den führenden Nullbits von `SHA1(omega ‖ dezimal(offset))`.

## Voice

```
C->S Voice:   vid u16 | codec u8 | data
S->C Voice:   vid u16 | talker clid u16 | codec u8 | data       (leere data = Ende der Übertragung)
C->S Whisper: vid u16 | codec u8 | n_chan u8 | n_cli u8 | chan u64* | clid u16* | data
```

Codecs: 4 = Opus Voice, 5 = Opus Music.

## Interop-Test gegen den Original-Server (verifiziert)

`ts3server` 3.13.8 lief in Docker auf `debian:bookworm-slim` mit `ca-certificates` (ohne die stürzt der Server beim Start ab). Der Rust-Client hat dort erfolgreich:

- per `initivexpand2` (Ed25519 + echte Lizenzkette) verbunden; das Version-Sign-Paar wird akzeptiert,
- den Channel-Baum geladen, Channel- und Privatnachrichten gesendet, einen Channel angelegt und sauber getrennt,
- Voice relayt: Client A sendet Opus-Frames, Client B erkennt „talking“.

Werkzeug dafür: `cargo run --example probe -- <addr> <variante>`. Es fährt den Init-Handshake, schickt `clientek`/`clientinit` und gibt jede Serverantwort samt Key-Diagnose aus.

## Offene Punkte

- Der echte TS6-Client gegen den Rust-Server ist nicht getestet, da der Client nicht installiert ist. Der Rust-Server sendet im Ed25519-Modus eine Kette mit eigener Root. Die akzeptiert der Original-Client nicht, deshalb ist Legacy der Default.
- `INIT_VERSION`, Fehler-IDs und einzelne `initserver`-Felder sind best effort.
- QuickLZ-Dekompression (Level 1/3) ist nur mit Stored-Blöcken getestet. Der echte Server hat im Test nichts komprimiert, weil die Commands klein waren.
