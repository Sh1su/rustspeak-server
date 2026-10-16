#!/usr/bin/env node
// Example bot for the RustSpeak bot interface (no dependencies, Node 18+).
//
//   node bots/echo-bot.js --key <bot key> [--host 127.0.0.1] [--port 10013] [--name EchoBot] [--channel /1]
//
// Create the key in RustSpeak (Rechte → Bots verwalten …) or via ServerQuery
// (`botkeyadd name=EchoBot`). The bot shows up as a normal client; write it a
// private message or use these commands in its channel:
//   !ping            → pong
//   !help            → list of commands
//   !zeit            → current server time of the bot
//   !komm            → bot joins your channel
//   anything else in a private chat is echoed back

const net = require('net');

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []));
const HOST = args.host || '127.0.0.1';
const PORT = Number(args.port || 10013);
const KEY = args.key || process.env.RUSTSPEAK_BOT_KEY;
if (!KEY) {
  console.error('Bot-Schlüssel fehlt: --key <schlüssel> oder RUSTSPEAK_BOT_KEY setzen');
  process.exit(1);
}

// ---------------------------------------------------------------- TS3 command syntax

const ESC = [['\\', '\\\\'], ['/', '\\/'], [' ', '\\s'], ['|', '\\p'], ['\x07', '\\a'], ['\b', '\\b'], ['\f', '\\f'], ['\n', '\\n'], ['\r', '\\r'], ['\t', '\\t'], ['\v', '\\v']];
const escape = s => String(s).replace(/[\\/ |\x07\b\f\n\r\t\v]/g, c => ESC.find(([a]) => a === c)[1]);
const unescape = s => s.replace(/\\(.)/g, (_, c) => ({ '\\': '\\', '/': '/', s: ' ', p: '|', a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' }[c] ?? c));

/** "name k=v k=v|k=v" → { name, items: [{k: v}, …] } */
function parse(line) {
  const sp = line.indexOf(' ');
  const name = sp < 0 ? line : line.slice(0, sp);
  const rest = sp < 0 ? '' : line.slice(sp + 1);
  const items = rest.split('|').map(part => {
    const o = {};
    for (const kv of part.split(' ').filter(Boolean)) {
      const eq = kv.indexOf('=');
      if (eq < 0) o[kv] = '';
      else o[kv.slice(0, eq)] = unescape(kv.slice(eq + 1));
    }
    return o;
  });
  return { name, items, args: items[0] || {} };
}

const build = (name, args = {}) => [name, ...Object.entries(args).map(([k, v]) => `${k}=${escape(v)}`)].join(' ');

// ---------------------------------------------------------------- bot

const sock = net.connect(PORT, HOST);
let buf = '';
let me = 0;
const clients = new Map(); // clid -> {nickname, channel}
const channels = new Map(); // cid -> name

function send(name, args) {
  sock.write(build(name, args) + '\n');
}
const reply = (mode, target, msg) => send('sendtextmessage', { targetmode: mode, target, msg });

sock.on('connect', () => {
  console.log(`Verbunden mit ${HOST}:${PORT}`);
});

sock.on('data', d => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i).replace(/\r$/, '');
    buf = buf.slice(i + 1);
    if (line) onLine(line);
  }
});

sock.on('close', () => {
  console.log('Verbindung beendet');
  process.exit(0);
});

function onLine(line) {
  if (line.startsWith('RSBOT')) {
    const login = { key: KEY, client_nickname: args.name || 'EchoBot', client_description: 'Beispiel-Bot · !help' };
    if (args.channel) login.client_default_channel = args.channel;
    return send('login', login);
  }
  const c = parse(line);
  switch (c.name) {
    case 'error':
      if (c.args.id !== '0') console.log(`Fehler ${c.args.id}: ${c.args.msg}`);
      break;
    case 'initserver':
      me = Number(c.args.aclid);
      console.log(`Angemeldet als Client ${me} auf „${c.args.virtualserver_name}“`);
      break;
    case 'channellist':
      for (const it of c.items) channels.set(Number(it.cid), it.channel_name);
      break;
    case 'notifycliententerview':
      for (const it of c.items) clients.set(Number(it.clid), { nickname: it.client_nickname, channel: Number(it.ctid) });
      break;
    case 'notifyclientleftview':
      clients.delete(Number(c.args.clid));
      break;
    case 'notifyclientmoved':
      for (const it of c.items) if (clients.has(Number(it.clid))) clients.get(Number(it.clid)).channel = Number(it.ctid);
      break;
    case 'notifyclientpoke':
      reply(1, c.args.invokerid, `Hallo ${c.args.invokername}, du hast mich angestupst! Schreib mir !help.`);
      break;
    case 'notifytextmessage':
      onMessage(c.args);
      break;
  }
}

function onMessage(m) {
  const from = Number(m.invokerid);
  if (from === me) return;
  const mode = Number(m.targetmode);
  const text = (m.msg || '').trim();
  const target = mode === 1 ? from : 0;
  console.log(`[${mode === 1 ? 'privat' : mode === 2 ? 'channel' : 'server'}] ${m.invokername}: ${text}`);
  const cmd = text.toLowerCase();
  if (cmd === '!ping') return reply(mode, target, 'pong');
  if (cmd === '!help') return reply(mode, target, 'Befehle: !ping, !zeit, !komm, !help – privat schicke ich alles zurück.');
  if (cmd === '!zeit') return reply(mode, target, new Date().toLocaleString('de-DE'));
  if (cmd === '!komm') {
    const ch = clients.get(from)?.channel;
    if (ch) send('clientmove', { clid: me, cid: ch });
    return reply(1, from, ch ? `Ich komme in „${channels.get(ch) || ch}“.` : 'Ich weiß nicht, wo du bist.');
  }
  if (mode === 1) reply(1, from, `Echo: ${text}`);
}

process.on('SIGINT', () => {
  send('quit');
  sock.end();
});
