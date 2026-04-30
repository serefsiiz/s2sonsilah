'use strict';

// MITM TCP Proxy — bir private server'a bağlanan client paketlerini yakala.
//
// KULLANIM:
//   1. Bu dosyayı düzenle: REMOTE_HOST + REMOTE_PORT'u hedef özel sunucuya çevir.
//   2. node mitm_proxy.js
//   3. Client'ı 127.0.0.1:LOCAL_PORT'a yönlendir (hosts dosyası VEYA client config).
//   4. Maça gir, mitm_capture.txt dosyasını izle.
//
// Bütün paketler hex+ASCII olarak loglanır.
// Hermit cipher decoder yoksa raw ciphertext görürsün — yine de paket boyutu/sıklığı bilgi verir.

const net = require('net');
const dgram = require('dgram');
const fs  = require('fs');
const path = require('path');

// ===== CONFIG =====
// D187 (cdgame-w) private server — args dosyasından çıktı:
// +gs_ip 93.158.236.130 +gs_port 12000
//
// Birden fazla MITM_TARGET tanımı yapabilirsin; her biri kendi local porta bind olur,
// log aynı dosyaya tag ile akar. Auth (12000) + Lobby (13000) ikisini birden yakala.
const REMOTE_HOST = '93.158.236.130';
// SN_ServerInfo decoded: ip=93.158.236.130, port (entry+80 LE u16) = 0x2EE1 = 12001
// Lobby D187'de 13000 DEĞİL → 12001. Bizim default 13000 yanlış olduğu için lobiye giremiyorduk.
const TARGETS = [
    { localPort: 12000, remotePort: 12000, tag: 'AUTH'  },  // auth/login (gs_ip:gs_port)
    { localPort: 12001, remotePort: 12001, tag: 'LOBBY' },  // ★ lobby — server-select sonrası buraya geçer
    { localPort: 13000, remotePort: 13000, tag: 'LOB13' },  // yedek (eski Joygame default), bizimkinde olabilir
];

// SN_Hosting_HostConnect (0x420303) decoded: byte 0-1 LE u16 = port (0x6CF2 = 27890), byte 2-16 = IP ASCII
// Bu UDP port'unu da MITM eylemek için ekledim. UDP proxy aşağıda dgram ile listen + forward.
//
// HackShield UDP listening enum yapabiliyor — UDP_ENABLED=false yaparsan sadece TCP, server-side
// anti-cheat tetikleyici azalır. Server-select'i geçemezsen önce false dene.
const UDP_ENABLED = false;
const UDP_TARGETS = [
    { localPort: 27890, remotePort: 27890, tag: 'DEDI-UDP' },  // dedi gameplay UDP — match-start sonrası buraya bağlanır
];
const LOG_FILE    = path.resolve(__dirname, 'mitm_capture.txt');

// Hermit cipher key — bizim lobby'den biliyoruz (varsa decode dener)
// Eski lobby'de keyByte 0xF için CRC32 XOR kullanılıyor; basit XOR sonrası opcode görünür
function tryDecodeHeader(buf) {
    if (buf.length < 16) return null;
    // Bizim header format'ı (kendi lobby'mizde kullandığımız):
    // 16 bytes: [4-byte CRC?][4-byte size][4-byte opcode][4-byte ?]
    // Plain mode'da opcode offset 8'de u24 LE
    const opcodePlain = buf.readUInt32LE(8) & 0xFFFFFF;
    return { opcodePlain };
}

function logLine(line) {
    fs.appendFileSync(LOG_FILE, line + '\n');
    console.log(line);
}

function hexDump(buf, max = 64) {
    const slice = buf.slice(0, max);
    return slice.toString('hex') + (buf.length > max ? `... (+${buf.length - max}B)` : '');
}

// ===== Hermit cipher (CRC32 XOR) — gerekli rewrite için =====
const crcTable = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        t[n] = c >>> 0;
    }
    return t;
})();
const KEY = 0x0F;

function decryptOne(buf, off) {
    if (off + 16 > buf.length) return null;
    const slice = buf.slice(off, Math.min(off + 0x4000, buf.length));
    const out = Buffer.from(slice);
    let crc = 0xFFFFFFFF;
    for (let i = 4; i < 16; i++) {
        const orig = slice[i];
        out[i] = KEY ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    out.slice(4, 6).swap16();
    out.slice(6, 8).swap16();
    out.slice(12, 16).swap32();
    const size = out.readUInt16LE(6);
    if (size < 16 || size > slice.length) return null;
    for (let i = 16; i < size; i++) {
        const orig = slice[i];
        out[i] = KEY ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    return { plain: out.slice(0, size), size, opcode: out.readUInt32LE(12) & 0xFFFFFF, sequence: out.readUInt16LE(4) };
}

// Plain LE-header packet → encrypt → wire bytes (sub-packet)
function encryptOne(plain) {
    const size = plain.readUInt16LE(6);
    const out  = Buffer.alloc(size);
    plain.copy(out, 0, 0, size);
    out.writeUInt16BE(out.readUInt16LE(4),  4);
    out.writeUInt16BE(out.readUInt16LE(6),  6);
    out.writeUInt32BE(out.readUInt32LE(12), 12);
    let crc = 0xFFFFFFFF;
    for (let i = 4; i < size; i++) {
        const orig = i < 16 ? out[i] : plain[i];
        const b = KEY ^ (crcTable[i] & 0xFF) ^ orig;
        out[i] = b;
        crc = crcTable[(b ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    out.writeUInt32BE((~crc) >>> 0, 0);
    return out;
}

// SN_ServerInfo (0x220101): per-entry IP at offset 5 (15 bytes ASCII), port at offset 80 (LE u16).
// Header 7 bytes, ENTRY 98 bytes.
// IP rewrite: tüm "93.158.236.130" → "127.0.0.1" yap, port aynı kalsın (12001).
function rewriteServerInfo(plain) {
    const HEADER = 7, ENTRY = 98;
    if (plain.length < 16 + HEADER) return plain;
    const payload = plain.slice(16);
    const count = payload[1];
    const out = Buffer.from(plain);
    for (let e = 0; e < count; e++) {
        const base = 16 + HEADER + e * ENTRY;
        if (base + 15 > out.length) break;
        const ipStr = out.slice(base + 5, base + 20).toString('ascii').replace(/\0.*$/, '');
        const portVal = out.readUInt16LE(base + 80);
        const newIp = '127.0.0.1';
        // 15-byte fixed field: write ASCII + null pad
        out.fill(0, base + 5, base + 20);
        out.write(newIp, base + 5, 15, 'ascii');
        logLine(`         [REWRITE] SN_ServerInfo entry${e}: ip="${ipStr}" port=${portVal} → ip="${newIp}" port=${portVal}`);
    }
    return out;
}

// SN_Hosting_HostConnect (0x420303): payload byte 0-1 LE u16 = UDP port, byte 2-16 = IP ASCII (15 bytes).
// Client bu paketi alınca dedi UDP'sine bağlanır → IP'yi 127.0.0.1'e rewrite et ki bizim UDP proxy yakalasın.
function rewriteHostConnect(plain) {
    if (plain.length < 16 + 17) return plain;
    const out = Buffer.from(plain);
    const payloadStart = 16;
    const portVal = out.readUInt16LE(payloadStart + 0);
    const ipStr = out.slice(payloadStart + 2, payloadStart + 17).toString('ascii').replace(/\0.*$/, '');
    const newIp = '127.0.0.1';
    out.fill(0, payloadStart + 2, payloadStart + 17);
    out.write(newIp, payloadStart + 2, 15, 'ascii');
    logLine(`         [REWRITE] SN_Hosting_HostConnect: ip="${ipStr}" port=${portVal} → ip="${newIp}" port=${portVal}`);
    return out;
}

// TCP buffer'da gelen 1+ paketi çöz, gerekirse rewrite et, tekrar encrypt et.
// Returned buffer 1:1 boyutta olmalı (size değişmiyor IP rewrite'da, padding vardı).
function maybeRewrite(buf) {
    let off = 0;
    const parts = [];
    let modified = false;
    while (off + 16 <= buf.length) {
        const r = decryptOne(buf, off);
        if (!r) {
            parts.push(buf.slice(off));
            break;
        }
        if (r.opcode === 0x220101) {
            const rewritten = rewriteServerInfo(r.plain);
            const enc = encryptOne(rewritten);
            if (enc.length === r.size) {
                parts.push(enc);
                modified = true;
                off += r.size;
                continue;
            }
        }
        if (r.opcode === 0x420303 && UDP_ENABLED) {
            const rewritten = rewriteHostConnect(r.plain);
            const enc = encryptOne(rewritten);
            if (enc.length === r.size) {
                parts.push(enc);
                modified = true;
                off += r.size;
                continue;
            }
        }
        parts.push(buf.slice(off, off + r.size));
        off += r.size;
    }
    if (!modified) return buf;
    return Buffer.concat(parts);
}

// Dosyaya FULL hex yaz (truncate yok). Konsol'da kısaltılmış, dosyada tam.
const FULL_LOG = path.resolve(__dirname, 'mitm_capture_full.txt');
fs.writeFileSync(FULL_LOG, `MITM full hex log started ${new Date().toISOString()}\n\n`);
function logFull(line) { fs.appendFileSync(FULL_LOG, line + '\n'); }

let connId = 0;

function startProxy(target) {
    const server = net.createServer((clientSock) => {
        const id = ++connId;
        const tag = `${target.tag}-c${id.toString().padStart(3, '0')}`;
        logLine(`\n========================================`);
        logLine(`[${tag}] NEW connection from ${clientSock.remoteAddress}:${clientSock.remotePort}`);
        logLine(`[${tag}] forwarding to ${REMOTE_HOST}:${target.remotePort}`);

        const upstream = net.createConnection(target.remotePort, REMOTE_HOST, () => {
            logLine(`[${tag}] upstream connected`);
        });

        let cToS = 0, sToC = 0;

        clientSock.on('data', (buf) => {
            cToS++;
            const dec = tryDecodeHeader(buf);
            const opStr = dec ? ` opcode_plain=0x${dec.opcodePlain.toString(16)}` : '';
            logLine(`[${tag}] CLIENT→SERVER #${cToS} ${buf.length}B${opStr}`);
            logLine(`         ${hexDump(buf, 80)}`);
            logFull(`[${tag}] C→S #${cToS} ${buf.length}B${opStr}\n         ${buf.toString('hex')}`);
            upstream.write(buf);
        });

        upstream.on('data', (buf) => {
            sToC++;
            const dec = tryDecodeHeader(buf);
            const opStr = dec ? ` opcode_plain=0x${dec.opcodePlain.toString(16)}` : '';
            logLine(`[${tag}] SERVER→CLIENT #${sToC} ${buf.length}B${opStr}`);
            logLine(`         ${hexDump(buf, 80)}`);
            logFull(`[${tag}] S→C #${sToC} ${buf.length}B${opStr}\n         ${buf.toString('hex')}`);
            // Auth proxy: SN_ServerInfo (0x220101) IP rewrite — client lobby'ye local proxy'den gelsin.
            // Lobby proxy: SN_Hosting_HostConnect (0x420303) IP rewrite — client UDP dedi'ye local proxy'den gelsin.
            const shouldRewrite = (target.tag === 'AUTH' || target.tag === 'LOBBY' || target.tag === 'LOB13');
            const out = shouldRewrite ? maybeRewrite(buf) : buf;
            clientSock.write(out);
        });

        const cleanup = (who, err) => {
            logLine(`[${tag}] ${who} closed${err ? ` err=${err.message}` : ''}`);
            clientSock.destroy();
            upstream.destroy();
        };
        clientSock.on('close', () => cleanup('client'));
        clientSock.on('error', (e) => cleanup('client', e));
        upstream.on('close',   () => cleanup('upstream'));
        upstream.on('error',   (e) => cleanup('upstream', e));
    });

    server.on('error', (e) => {
        logLine(`[${target.tag}] LISTEN ERROR on ${target.localPort}: ${e.message}`);
    });

    server.listen(target.localPort, '127.0.0.1', () => {
        logLine(`[${target.tag}] listening on 127.0.0.1:${target.localPort} → ${REMOTE_HOST}:${target.remotePort}`);
    });
}

// UDP proxy — dedi gameplay paketleri (kamera bind, spawn-at-point, position updates).
// Tek client varsayımı: client→server eşlemesi son gönderen address+port'la yapılır.
// Multi-client için NAT-table kullanılması lazım ama bu geliştirme/RE için tek-client yeterli.
function startUdpProxy(target) {
    const sock = dgram.createSocket('udp4');
    let lastClient = null;          // client'ın address+port (response'lar buna gider)
    let upstreamSock = null;        // upstream'e giden ayrı socket (her client için ayrı path olur)

    sock.on('error', (e) => logLine(`[${target.tag}] UDP error: ${e.message}`));
    sock.on('message', (msg, rinfo) => {
        if (rinfo.address !== '127.0.0.1') {
            // Upstream'den dönen paket olamaz — bu LOCAL CLIENT'tan geliyor
            return;
        }
        // Local client (TheRaw.exe) → dedi
        lastClient = { address: rinfo.address, port: rinfo.port };
        logLine(`[${target.tag}] CLIENT(${rinfo.port})→DEDI ${msg.length}B`);
        logFull(`[${target.tag}] UDP C→S ${msg.length}B (from :${rinfo.port})\n         ${msg.toString('hex')}`);

        if (!upstreamSock) {
            upstreamSock = dgram.createSocket('udp4');
            upstreamSock.on('message', (msg2, rinfo2) => {
                logLine(`[${target.tag}] DEDI(${rinfo2.address}:${rinfo2.port})→CLIENT ${msg2.length}B`);
                logFull(`[${target.tag}] UDP S→C ${msg2.length}B (from ${rinfo2.address}:${rinfo2.port})\n         ${msg2.toString('hex')}`);
                if (lastClient) {
                    sock.send(msg2, lastClient.port, lastClient.address);
                }
            });
            upstreamSock.on('error', (e) => logLine(`[${target.tag}] UDP upstream error: ${e.message}`));
        }
        upstreamSock.send(msg, target.remotePort, REMOTE_HOST);
    });

    sock.bind(target.localPort, '127.0.0.1', () => {
        logLine(`[${target.tag}] UDP listening on 127.0.0.1:${target.localPort} → ${REMOTE_HOST}:${target.remotePort}`);
    });
}

fs.writeFileSync(LOG_FILE, `MITM proxy started ${new Date().toISOString()}\n` +
                            `target=${REMOTE_HOST} (D187 / cdgame-w private server)\n\n`);
console.log(`log file: ${LOG_FILE}`);
TARGETS.forEach(startProxy);
if (UDP_ENABLED) UDP_TARGETS.forEach(startUdpProxy);
else logLine(`[INFO] UDP proxy DISABLED (UDP_ENABLED=false). Set true to capture dedi gameplay UDP.`);
