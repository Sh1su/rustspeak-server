# RustSpeak Server

Ein Voice-Server für das TeamSpeak-3-Protokoll, neu geschrieben in Rust. Passender Client: [RustSpeak](https://github.com/Sh1su/rustspeak-client).

| Port | Dienst |
|---|---|
| 9987/udp | Sprache (TS3-Protokoll) |
| 9987/tcp | Video-Relay (WebSocket) für Bildschirm und Webcam |
| 10011/tcp | ServerQuery |
| 10013/tcp | Bot-Schnittstelle |

| Ordner | Inhalt |
|---|---|
| `server/` | `ts3-server` |
| `tsproto/` | Protokoll-Bibliothek (Pakete, Krypto, Handshake, Lizenzkette, QuickLZ, zuverlässiger Command-Transport) |
| `bots/` | Beispiel-Bot (Node.js) |
| `PROTOCOL.md` | Reverse-Engineering-Befunde |

## Docker

```bash
docker compose up -d
```

Oder ohne Compose:

```bash
docker build -t rustspeak-server .
```

```bash
docker run -d --name rustspeak -p 9987:9987/udp -p 9987:9987/tcp -p 10011:10011 -p 10013:10013 -v rustspeak-data:/data rustspeak-server
```

Die Daten (Channels, Gruppen, Rechte, Schlüssel) liegen im Volume unter `/data/ts3server_state.json`. Das ServerQuery-Passwort und den ersten Admin-Berechtigungsschlüssel zeigt der erste Start im Log:

```bash
docker logs rustspeak
```

Weitere Optionen werden einfach angehängt, z. B. `docker run … rustspeak-server --security-level 20`.

## Ohne Docker bauen

```bash
cargo build --release
```

```bash
target/release/ts3-server
```

Beim ersten Start legt der Server `ts3server_state.json` an und gibt das ServerQuery-Passwort für `serveradmin` aus. Optionen:

- `--port`
- `--query-port`
- `--security-level`
- `--handshake legacy|ed25519`
- `--bot-port`: TCP-Port der Bot-Schnittstelle (Standard 10013, `0` schaltet sie ab), siehe „Bots“
- `--video-port`: TCP-Port des Video-Relays (WebSocket) für Bildschirm und Webcam. Standard ist dieselbe Nummer wie der Sprachport (9987/TCP), `0` schaltet es ab. Diese Erweiterung gehört nicht zum TS3-Protokoll; Clients holen sich mit dem Befehl `videotoken` ein Einmal-Token.

Solange es keinen Server-Admin gibt, gibt der Server beim Start einen Berechtigungsschlüssel aus (`token=…`). Einlösen in RustSpeak: **Rechte → Berechtigungsschlüssel verwenden**. Das Rechtesystem folgt TeamSpeak: Server- und Kanalgruppen mit Rechten, und Kraft-Werte (*power*) werden gegen die benötigten Werte (*needed power*) des Ziels verglichen. Standardgruppen sind Server Admin, Normal und Guest sowie Channel Admin, Operator und Guest. Per ServerQuery geht es ebenfalls: `servergroupaddclient`, `servergroupaddperm`, `privilegekeyadd`, `banadd` und so weiter.

## Bots

Bots sind Programme, die sich über die Bot-Schnittstelle (TCP 10013) anmelden und dann wie normale Clients im Channelbaum stehen, mit einem violetten „BOT“-Kennzeichen. Man kann sie privat oder im Channel anschreiben, anstupsen, verschieben, kicken und ihnen Gruppen geben. Jeder Bot-Schlüssel hat eine feste Identität (`bot:<id>`), Gruppen bleiben also erhalten.

1. Bot anlegen: in RustSpeak **Rechte → Bots verwalten … → Bot anlegen** (Recht `b_virtualserver_bot_manage`) oder per ServerQuery `botkeyadd name=MeinBot`. Der Schlüssel landet in der Zwischenablage.
2. Beispiel-Bot starten:

```bash
node bots/echo-bot.js --key <bot-schlüssel> --host 127.0.0.1
```

Der Beispiel-Bot antwortet auf `!ping`, `!zeit`, `!komm` und `!help` und schickt private Nachrichten zurück.

Das Protokoll ist zeilenbasiert und nutzt die TS3-Befehlssyntax (Escaping wie bei ServerQuery):

```text
<- RSBOT 1
-> login key=<schlüssel> client_nickname=MeinBot client_default_channel=/1
<- initserver … | channellist … | notifycliententerview … | error id=0 msg=ok
<- notifytextmessage targetmode=1 msg=hallo invokerid=2 invokername=Alice …
-> sendtextmessage targetmode=1 target=2 msg=hallo\szurück
<- error id=0 msg=ok
```

Nach dem Login bekommt der Bot dieselben Benachrichtigungen wie ein Sprach-Client und darf alle Client-Befehle senden (`sendtextmessage`, `clientmove`, `clientupdate`, `clientpoke`, `clientkick`, …), jeweils im Rahmen seiner Gruppenrechte. Jede Zeile wird mit `error id=… msg=…` beantwortet. Mit `quit` meldet sich der Bot ab. Bots bekommen keine Sprachdaten.

## Was funktioniert

- Komplettes TS3-Transportprotokoll: Init-Puzzle, AES-EAX, Acks/Resend, Fragmentierung, Ping/Pong.
- Beide Key-Exchanges: Legacy P-256 und Ed25519 mit Lizenzkette.
- Channels (permanent/temporär, Passwörter, Limits, Persistenz), Chat (privat/Channel/Server), Poke, Move, Kick, Client-Updates, Voice- und Whisper-Relay, Server- und Channelgruppen mit Rechten, Berechtigungsschlüssel, Bans, ServerQuery-Subset.
- Video-Relay für Bildschirmübertragung und Webcams (RustSpeak-Erweiterung), Bot-Schnittstelle.

## Nicht enthalten

- Dateiübertragung (Port 30033), WebQuery/SSH-Query, mehrere virtuelle Server.
