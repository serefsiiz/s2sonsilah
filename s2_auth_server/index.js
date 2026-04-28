'use strict';

// ==========================================================================
// S2: Son Silah — AUTH SERVER (port 12000)
//
// Tüm paket formatları GameClient.dll içindeki CDispatch_xxx vtable[1]
// handler'larından REVERSE edilerek belirlenmiştir. Magic offset YOK,
// her field IDA Pro'da decompile edilmiş parser kodu ile doğrulanmıştır.
//
// Reverse referansları (port 13338, GameClient.dll):
//   SA_JoyGameLogin   → sub_100D74A0   (sadece error check)
//   SA_Join           → sub_10030C90   (sadece error check)
//   SN_UserInfo       → sub_100D7A70   (nick @ +0, clan @ +25)
//   SN_Record         → sub_10031140   (5 u32 + 136 byte struct + 6 u32)
//   SN_ServerList     → sub_10032810   (count + N×20 byte entries)
//   SN_ServerInfo     → sub_1011EB80   (count + 5 byte hdr + N×98 byte)
//   SN_ChannelList    → sub_100BA790   (count + 5 byte hdr + N×57 byte)
//   SN_ItemList       → sub_10031000   (count + N×27 byte entries)
//   SN_SlotInfo       → sub_100312B0   (u32 array, 11 slot mapping)
//   SN_LockEnd        → sub_10032F30   (errcode + reason; 0/0 = success)
//   SA_AwayUser       → sub_100324C0   (errcode + reason + 2 u32)
// ==========================================================================

const net  = require('net');
const fs   = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const storage = require('../s2_shared/storage');
const PKT_ALL = require('../s2_shared/packet_ids');
const helpers = require('../s2_shared/packet_helpers');

// --------------------------------------------------------------------------
// CONFIG
// --------------------------------------------------------------------------

const CONFIG = {
    HOST            : '127.0.0.1',
    PORT            : 12000,
    MAX_PACKET_SIZE : 0x400,
    LOBBY_HOST      : '127.0.0.1',
    LOBBY_PORT      : 13000,
};

// --------------------------------------------------------------------------
// PACKET ID'LERİ
// --------------------------------------------------------------------------

const PKT = {
    // gelen
    CQ_HackShield    : 0x750101,
    CQ_JoyGameLogin  : 0x110111,
    CQ_Join          : 0x110124,
    CQ_AwayUser      : 0x220131,
    CQ_Heartbeat     : 0x20080,
    CQ_KeepAlive     : 0x20082,
    CQ_KeepAliveAck  : 0x20083,
    CQ_KeepAlive2    : 0x20084,
    CQ_GameInit      : 0x130000,

    // giden
    SA_JoyGameLogin  : 0x110112,
    SA_Join          : 0x110125,
    SA_AwayUser      : 0x220132,
    SN_UserInfo      : 0x210101,
    SN_Record        : 0x210103,
    SN_ServerList    : 0x220108,
    SN_ServerInfo    : 0x220101,
    SN_ChannelList   : 0x220102,
    SN_GroupList     : 0x220107,    // sub_100326F0 — group/region list (66-byte entry)
    SN_ItemList      : 0x210111,
    SN_SlotInfo      : 0x210113,
    SN_LockEnd       : 0x210121,
    SA_HeartbeatAck  : 0x20081,
    SA_KeepAliveAck  : 0x20083,
};

// --------------------------------------------------------------------------
// HERMIT PACKET FORMAT (16-byte header)
//   [0..3]  CRC32 (plain mode: sabit 0x117b5a78)
//   [4..5]  sequence (u16 LE)
//   [6..7]  packet size (u16 LE, header dahil)
//   [8..11] reserved (0)
//   [12..15] opcode (u32 LE)
//   [16..]  payload
// --------------------------------------------------------------------------

const crcTable = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        t[n] = c >>> 0;
    }
    return t;
})();

function cryptPacket(buf, keyByte, sequence) {
    const size = buf.readUInt16LE(6);
    const out  = Buffer.alloc(size);
    buf.copy(out, 0, 0, size);
    out.writeUInt16BE(sequence,                4);
    out.writeUInt16BE(size,                    6);
    out.writeUInt32BE(buf.readUInt32LE(12),   12);
    let crc = 0xFFFFFFFF;
    for (let i = 4; i < size; i++) {
        const orig = i < 16 ? out[i] : buf[i];
        const b = keyByte ^ (crcTable[i] & 0xFF) ^ orig;
        out[i] = b;
        crc = crcTable[(b ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    out.writeUInt32BE((~crc) >>> 0, 0);
    return out;
}

function decryptPacket(buf, keyByte) {
    if (buf.length < 16) return null;
    const out = Buffer.from(buf);
    let crc = 0xFFFFFFFF;
    for (let i = 4; i < 16; i++) {
        const orig = buf[i];
        out[i] = keyByte ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    out.slice(4,  6).swap16();
    out.slice(6,  8).swap16();
    out.slice(12, 16).swap32();
    const size = out.readUInt16LE(6);
    if (size < 16 || size > buf.length || size > 0x400) return null;
    for (let i = 16; i < size; i++) {
        const orig = buf[i];
        out[i] = keyByte ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    const stored     = buf.readUInt32BE(0);
    const calculated = (~crc) >>> 0;
    if (calculated !== stored) return null;
    return out;
}

function peekEncryptedSize(buf, keyByte) {
    if (buf.length < 16) return -1;
    const b6 = keyByte ^ buf[6] ^ (crcTable[6] & 0xFF);
    const b7 = keyByte ^ buf[7] ^ (crcTable[7] & 0xFF);
    return (b6 << 8) | b7;
}

function buildPacketPlain(sequence, opcode, payload) {
    const payloadLen = payload ? payload.length : 0;
    const size = 16 + payloadLen;
    const buf  = Buffer.alloc(size);
    buf.writeUInt32LE(0x117b5a78, 0);
    buf.writeUInt16LE(sequence,   4);
    buf.writeUInt16LE(size,       6);
    buf.writeUInt32LE(0,          8);
    buf.writeUInt32LE(opcode,    12);
    if (payload) payload.copy(buf, 16);
    return buf;
}

function sendPacket(socket, ctx, opcode, payload = null) {
    return new Promise((resolve, reject) => {
        try {
            const seq   = ctx.sequence++;
            const plain = buildPacketPlain(seq, opcode, payload);
            const wire  = ctx.encrypted ? cryptPacket(plain, ctx.keyByte, seq) : plain;
            socket.write(wire, err => err ? reject(err) : resolve());
            const tag = ctx.encrypted ? 'ENC' : 'plain';
            console.log(`[AUTH→${ctx.id.slice(0,6)}] sent 0x${opcode.toString(16)} ${PKT_ALL.NAME(opcode)} (${payload ? payload.length : 0} byte, seq ${seq}, ${tag})`);
        } catch (err) {
            reject(err);
        }
    });
}

// --------------------------------------------------------------------------
// STATE
// --------------------------------------------------------------------------

const clients = new Map();

function createClient(socket) {
    const ctx = {
        id         : uuidv4(),
        sequence   : 1,
        encrypted  : null,
        keyByte    : 0x0F,
        recvBuffer : null,
        username   : null,
        password   : null,
        userId     : 0,
        loggedIn   : false,
    };
    clients.set(socket, ctx);
    console.log(`[AUTH] client connected: ${ctx.id.slice(0,6)} from ${socket.remoteAddress}`);
    return ctx;
}

function destroyClient(socket) {
    const ctx = clients.get(socket);
    if (ctx) console.log(`[AUTH] client disconnected: ${ctx.id.slice(0,6)}`);
    clients.delete(socket);
}

// --------------------------------------------------------------------------
// PAKET BUILDER'LAR
// Tüm format'lar reverse edilmiş, magic offset yok.
// --------------------------------------------------------------------------

// ----- SA_JoyGameLogin / SA_Join -----
// sub_100D74A0 → sub_10191740 dispatcher (FULL REVERSE):
//   payload[0..1] u16 errcode = error CATEGORY (sub_10191740 switch a3)
//   payload[2..5] u32 reason  = error REASON code (sub_10191740 a2; sub-case)
//
// Sub_10191740 errcode kategorileri (case a3):
//   0x6101 → "NetmarbleAuthModule_ERROR_%d"     (Netmarble auth)
//   0x6102 → "NetmarbleBillingModule_ERROR_%d"  (Netmarble billing)
//   0x6104 → LOGIN errors (sub-switch on reason a2 → string ID 511..520)
//   0x7001 → "ComModule_ERROR_%d"
//   0x7101 → "DB_MSG_ERROR_%d"
//   0x7201 → "ADOModule_ERROR_%d"
//   0x8201 → ?
//   default → "MSG_ERROR_%08x" + popup
//
// 0x6104 LOGIN sub-codes (reason u32):
//   1 → string 513   (Already Logged In)
//   2 → string 514   (Wrong Password)
//   3 → string 511   (Login Failed / generic)         + ErrorCode shown
//   4 → string 517   (Account Banned?)
//   5 → string 520   (?)
//   6 → string 519   (?)
//   7 → string 512   (User Not Found?)
//   8 → string 515   (?)                              + ErrorCode shown
//   9 → string 516   (?)                              + ErrorCode shown
//  -1 → string 518   (Server Error)                   + ErrorCode shown
//
// errcode=0 + reason=0 = SUCCESS (early return, no popup).
const LOGIN_ERR = {
    OK             : { errcode: 0,      reason: 0 },
    ALREADY_LOGGED : { errcode: 0x6104, reason: 1 },
    WRONG_PASSWORD : { errcode: 0x6104, reason: 2 },
    LOGIN_FAILED   : { errcode: 0x6104, reason: 3 },
    ACCOUNT_BANNED : { errcode: 0x6104, reason: 4 },
    USER_NOT_FOUND : { errcode: 0x6104, reason: 7 },
    SERVER_ERROR   : { errcode: 0x6104, reason: -1 >>> 0 },
};

function buildErrorAck(errcode = 0, reason = 0) {
    const p = Buffer.alloc(6);
    p.writeUInt16LE(errcode & 0xFFFF, 0);
    p.writeUInt32LE(reason  >>> 0,    2);
    return p;
}

async function send_SA_JoyGameLogin(socket, ctx, errcode = 0, reason = 0) {
    await sendPacket(socket, ctx, PKT.SA_JoyGameLogin, buildErrorAck(errcode, reason));
}

async function send_SA_Join(socket, ctx, errcode = 0, reason = 0) {
    await sendPacket(socket, ctx, PKT.SA_Join, buildErrorAck(errcode, reason));
}

// ----- SN_UserInfo -----
// sub_100D7A70:
//   payload[0..]  null-terminated nick (kullanılan max ~25)
//   payload[25..] null-terminated clan/secondary name (state+208'e yazılır)
// Min payload = 25 + 25 = 50 byte, sıfır padding.
async function send_SN_UserInfo(socket, ctx) {
    const NICK_LEN = 25;
    const CLAN_LEN = 25;
    const p = Buffer.alloc(NICK_LEN + CLAN_LEN);
    const nick = (ctx.username || 'Player').slice(0, NICK_LEN - 1);
    p.write(nick, 0, NICK_LEN - 1, 'utf8');   // payload[0..24], null-terminated
    // payload[25..49] = clan name (kullanıcının üye olduğu klan, varsa)
    const clan = ctx.username ? storage.getClan(ctx.username) : null;
    if (clan && clan.name) {
        p.write(clan.name.slice(0, CLAN_LEN - 1), 25, CLAN_LEN - 1, 'utf8');
    }
    await sendPacket(socket, ctx, PKT.SN_UserInfo, p);
}

// ----- SN_Record -----
// sub_10031140 — KRİTİK: parser a1 = TAM PACKET (16-byte header + payload).
// Yani a1+0x10 (=16) = payload[0]. Asm'den birebir doğrulandı:
//   mov edx, [eax+10h]   ; eax=a1, [eax+16] = payload[0..3] = level
//   mov [ecx+54h], edx   ; state[+84] = level
//   mov edx, [eax+0C2h]  ; [eax+194] = payload[178..181] = kills
//   mov [ecx+58h], edx   ; state[+88] = kills
//
// Reverse'lenmiş tam offset tablosu (PAYLOAD offsets):
//   payload[0..3]    → state[+84]  (level/rank)
//   payload[4..7]    → state[+96]  (wins)
//   payload[8..11]   → state[+100] (losses)
//   payload[12..15]  → state[+104] (draws)
//   payload[16..19]  → state[+108] (totalMatches)
//   payload[20..155] → 136 byte map record struct (sub_10084CB0)
//   payload[156..177]= padding
//   payload[178..181]→ state[+88]  (kills)
//   payload[182..185]→ state[+92]  (deaths)
//   payload[186..189]→ state[+120] (assists)
//   payload[190..193]→ state[+124] (headshots)
//   payload[194..197]→ state[+128] (exp)
//   payload[198..201]→ state[+132] (rank points)
// Min payload = 202 byte.
async function send_SN_Record(socket, ctx) {
    const s = ctx.username ? storage.getStats(ctx.username) : storage.defaultStats();
    const p = Buffer.alloc(202);
    p.writeUInt32LE(s.level        || 1,   0);
    p.writeUInt32LE(s.wins         || 0,   4);
    p.writeUInt32LE(s.losses       || 0,   8);
    p.writeUInt32LE(s.draws        || 0,  12);
    p.writeUInt32LE(s.totalMatches || 0,  16);
    // payload[20..155] = map record struct (zero — henüz map oynanmadı)
    // payload[156..177] = padding
    p.writeUInt32LE(s.kills        || 0, 178);
    p.writeUInt32LE(s.deaths       || 0, 182);
    p.writeUInt32LE(s.assists      || 0, 186);
    p.writeUInt32LE(s.headshots    || 0, 190);
    p.writeUInt32LE(s.exp          || 0, 194);
    p.writeUInt32LE(s.rankPoints   || 0, 198);
    await sendPacket(socket, ctx, PKT.SN_Record, p);
}

// ----- SN_RankingInfo -----
// sub_10031110 — a1 TAM PACKET. Reverse:
//   *(this+112) = *(_DWORD *)(a1 + 22)  → payload[6..9]
//   *(this+116) = *(_DWORD *)(a1 + 26)  → payload[10..13]
// Min payload = 14 byte.
async function send_SN_RankingInfo(socket, ctx) {
    const s = ctx.username ? storage.getStats(ctx.username) : storage.defaultStats();
    const p = Buffer.alloc(14);
    p.writeUInt32LE(0,                  6);   // state+112: rank position (0 = unranked)
    p.writeUInt32LE(s.rankPoints || 0, 10);   // state+116: rank points
    await sendPacket(socket, ctx, 0x210105, p);
}

// ----- SN_RecordMapList -----
// sub_10031200 — a1 TAM PACKET:
//   *(unsigned __int8 *)(a1 + 17) = count → payload[1]
//   a1 + 18                       = entries → payload[2]
// Boş liste için min 2 byte yeterli.
async function send_SN_RecordMapList(socket, ctx) {
    const p = Buffer.alloc(2);
    p[0] = 0;
    p[1] = 0;   // count = 0
    await sendPacket(socket, ctx, 0x210123, p);
}

// NOT: SN_MainWeaponList (0x210122) ve SN_Achievement_* (0x2A01xx) GÖNDERİLMİYOR.
// SN_MainWeaponList parser'ı (sub_10031E80) "GameNoticePop" + "InGameShutDownPop" + 10s timer
// tetikliyor — yani server'dan gelirse client zorla shutdown'a gidiyor. Login bundle'da
// göndermek "PopUpIdentify" popup'larına yol açıyor.
// SN_Achievement_* opcode'ları (0x2A0101..0103) bu client'ta tanımsız (sadece debug log noise).

// ----- SN_ServerList -----
// sub_10032810: parser, reader stride = 0x14 (20 byte)
//   payload[0]   header byte (kullanılmıyor — parser sadece sayıyı okur)
//   payload[1]   u8 count
//   payload[2..] count × 20 byte entry
//
// Entry parser sub_10032210: 5 dword (20 byte) raw memcpy. Saklanan list:
//   *(globalManager + 24) + 592   (= dispatch list at +0x250)
//
// sub_10052520 LOOKUP (full reverse):
//   ECX = global list manager
//   arg1 = ServerInfo widget'in ilk string buffer'ı (= server entry[5..])
//          → SERVERLIST entry[10..] ile strcmp
//   1. eşleşme bulunca: ServerList entry[0..19] → a3 [20 byte struct]
//   2. ardından GROUPLIST entry'lerinden entry[5..] == a3+5 olanı arar
//   3. bulunca: GroupList entry'nin tam 66 byte'ını a4'e qmemcpy → output[10..]
//      ServerInfo widget'in "Savaş A." kolonunda gösterilen display name OLUYOR
//
// SONUÇ: ServerList entry[5..] = LINK KEY (GroupList entry[5..] ile eşleşmeli)
//        ServerList entry[10..] = SHORT KEY (ServerInfo entry[0..3] ile eşleşmeli)
async function send_SN_ServerList(socket, ctx) {
    // Her server bir grup'a bağlı. Aynı linkKey GroupList entry[5..]'da olmalı.
    const SERVERS = [
        { name: 'S2',  linkKey: 'GA' },   // Normal arena → group "GA"
        { name: 'S2K', linkKey: 'GK' },   // Klan arena   → group "GK"
    ];
    const ENTRY = 20;
    const p = Buffer.alloc(2 + SERVERS.length * ENTRY);
    p[0] = 0;
    p[1] = SERVERS.length;
    let off = 2;
    for (const s of SERVERS) {
        // entry[0..3] = u32 id (kullanılmıyor — gösterilmez)
        // entry[5..]  = link key (GroupList entry[5..]'a eşleşir)
        p.write(s.linkKey.slice(0, 4), off + 5,  4, 'ascii');
        // entry[10..] = short key (SN_ServerInfo entry[0..3]'e eşleşir, lookup için)
        p.write(s.name.slice(0, 9),    off + 10, 9, 'ascii');
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_ServerList, p);
}

// ----- SN_ServerInfo -----
// sub_10074F30 → sub_100735F0 parser: 98-byte entry, payload[7..] başlar.
//   payload[0]     header byte
//   payload[1]     u8 count
//   payload[2..6]  5 byte header padding
//   payload[7..]   count × 98 byte entry
//
// Entry layout — KESİN reverse + UI testi ile doğrulandı:
//   entry[0..4]    5 byte: short ID (struct+0) — SN_ChannelList lookup key
//   entry[5..20]   16 byte: IP ADDRESS string (struct+28) — connect kullanır
//   entry[21..75]  55 byte: server display name (struct+56 + wstring struct+84) — UI listede görünür
//   entry[76..79]  u32 → struct+652
//   entry[80..81]  u16 PORT → struct+656 — connect kullanır
//   entry[82..83]  u16 MAX users → struct+658 — doluluk paydası
//   entry[84..85]  u16 CURRENT users → struct+660 — doluluk payı
//   entry[86]      u8 SKIP flag (1 = entry'i gizle)
//   entry[87..91]  u8 × 5 STATUS FLAGS — sadece BİRİ 1 olmalı (struct+680'i belirler):
//                    +87 = 1 → struct+680 = 1
//                    +88 = 1 → struct+680 = 2
//                    +90 = 1 → struct+680 = 4
//                    +91 = 1 → struct+680 = 5
//                    hepsi 0 → struct+680 = 6
//                    (+89 byte parser'da kullanılmıyor)
//   entry[92..97]  padding
//
// SERVER ICON CASE ID'leri (UI string lookup'tan, sub_100785B0):
//   86  = UI_SYS_CLAN_ClanServer       (Klan sunucusu)
//   87  = UI_SYS_CLAN_ClanXServer      (Klan sunucusu — DOLU/X)
//   150 = GlobalUI_NormalServer        (Normal sunucu)
//   151 = GlobalUI_NormalServerX       (Normal sunucu — yüksek doluluk)
//   152 = GlobalUI_NormalXServer       (Normal sunucu — kapalı/dolu)
//   157 = GlobalUI_PCRoomServer        (PC Room sunucusu)
//   158 = GlobalUI_PCRoomServerX       (PC Room — yüksek doluluk)
//   159 = GlobalUI_PCRoomXServer       (PC Room — kapalı/dolu)
//
// struct+680 değeri (1-6) ile case ID arasındaki kesin mapping UI render
// kodunda yapılıyor; deneysel test için status flag'leri tek tek değiştirilebilir
// (entry+87/88/90/91 = 1 yaparak farklı struct+680 değerleri görüp icon'lara bakılır).
// SERVER_KIND enum — entry+87..+91 status flag'lerinden bir tanesi 1 olmalı
// → struct+680 değerini belirler. Kullanıcı testi (2026-04-27) sonucu:
//   struct+680 = 1 (entry+87 = 1) → CLAN MATCH-supported sunucu
//                                   (lobby'de "Klan Eşleşme" butonu görünür,
//                                    basınca direkt oda kurar)
//   struct+680 = 2,4,5,6          → Normal sunucu (klan match butonu yok)
//
// Server LIST ekranındaki ikonlar AYNI görünüyor — load göstergesi
// current/max users'tan hesaplanıyor (struct+680 ile alakasız).
const SK = {
    CLAN     : 'CLAN',       // entry+87 = 1 → struct+680 = 1 — Klan match destekli
    NORMAL_2 : 'NORMAL_2',   // entry+88 = 1 → struct+680 = 2 — Normal (variant 2)
    NORMAL_4 : 'NORMAL_4',   // entry+90 = 1 → struct+680 = 4 — Normal (variant 4)
    NORMAL_5 : 'NORMAL_5',   // entry+91 = 1 → struct+680 = 5 — Normal (variant 5)
    NORMAL_6 : 'NORMAL_6',   // hepsi 0     → struct+680 = 6 — Normal (default/PCRoom?)
};

async function send_SN_ServerInfo(socket, ctx) {
    // 2 server: 1 klan match destekli + 1 normal
    const SERVERS = [
        {
            shortId:     'S2',                    // SN_ChannelList lookup key
            ip:          CONFIG.LOBBY_HOST,
            displayName: 'S2: Son Silah (Normal)',
            port:        CONFIG.LOBBY_PORT,
            maxUsers:    100,
            currentUsers: 1,
            kind:        SK.NORMAL_2,             // klan match yok
        },
        {
            shortId:     'S2K',
            ip:          CONFIG.LOBBY_HOST,
            displayName: 'S2: Son Silah (Klan)',
            port:        CONFIG.LOBBY_PORT,
            maxUsers:    100,
            currentUsers: 1,
            kind:        SK.CLAN,                 // lobby'de klan match butonu görünür
        },
    ];
    const ENTRY = 98;
    const HEADER = 7;
    const p = Buffer.alloc(HEADER + SERVERS.length * ENTRY);
    p[0] = 0;
    p[1] = SERVERS.length;
    let off = HEADER;
    for (const s of SERVERS) {
        p.write(s.shortId.slice(0, 4),     off + 0,  4,  'ascii');
        p.write(s.ip.slice(0, 15),         off + 5,  15, 'ascii');
        p.write(s.displayName.slice(0, 54),off + 21, 54, 'utf8');

        p.writeUInt32LE(1,             off + 76);
        p.writeUInt16LE(s.port,        off + 80);
        p.writeUInt16LE(s.maxUsers,    off + 82);
        p.writeUInt16LE(s.currentUsers,off + 84);

        p.writeUInt8(0, off + 86);   // SKIP = 0 → görünür
        // Sadece BİR status flag 1 olmalı (sub_100735F0'da if-else if zinciri)
        if      (s.kind === SK.CLAN     ) p.writeUInt8(1, off + 87);
        else if (s.kind === SK.NORMAL_2 ) p.writeUInt8(1, off + 88);
        else if (s.kind === SK.NORMAL_4 ) p.writeUInt8(1, off + 90);
        else if (s.kind === SK.NORMAL_5 ) p.writeUInt8(1, off + 91);
        // SK.NORMAL_6 → hiçbiri set değil
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_ServerInfo, p);
}

// ----- SN_ChannelList -----
// sub_100BA790 → sub_100743A0 → sub_100742C0 parser zinciri.
// KRİTİK: sub_100743A0 payload[2..]'i STRING olarak okur, sub_10073420 ile
// LOOKUP eder (SN_ServerInfo entry[0..4] = server kısa ID ile match etmeli).
// Lookup başarısızsa parser çağrılmaz → channel list HIÇ doldurulmaz.
//   payload[0]      ?
//   payload[1]      u8 count
//   payload[2..6]   5 byte SERVER KEY STRING (null-terminated, "S2"-tarzı)
//   payload[7..]    count × 57 byte entry
//
// Entry layout (sub_10073BF0 + sub_100BACF0 SendList ile doğrulandı):
//   [0]      u8 type/category               → struct+0
//   [1..2]   u16 CURRENT users              → struct+2 (sub_100BACF0 doluluk payı)
//   [3..4]   u16 MAX users                  → struct+4 (doluluk paydası)
//   [5]      u8 flag                        → struct+6
//   [6..9]   4 byte (kullanılmıyor)
//   [10..13] u32 active flag (1 = görünür) → struct+576
//   [14..56] channel name string (max 43 byte) → struct+8 + wstring struct+36
//
// sub_100BACF0 her channel için Flash'a şunları gönderir:
//   - wstring channel name (struct+36)
//   - doluluk yüzdesi 0-9 (sub_10072B30 mantığı)
//   - 0.0 (placeholder)
// Tek bir SN_ChannelList paketi tek bir SERVER KEY için channel'ları taşıyabiliyor.
// Çoklu server için ayrı ayrı paket göndermek gerekiyor.
async function send_SN_ChannelList(socket, ctx, serverKey, channels) {
    const ENTRY = 57;
    const HEADER = 7;
    const p = Buffer.alloc(HEADER + channels.length * ENTRY);
    p[0] = 0;
    p[1] = channels.length;
    p.write(serverKey.slice(0, 4), 2, 4, 'ascii');   // payload[2..5] = lookup key
    let off = HEADER;
    for (const c of channels) {
        p.writeUInt8   (c.type,    off + 0);
        p.writeUInt16LE(c.current, off + 1);
        p.writeUInt16LE(c.max,     off + 3);
        p.writeUInt8   (0,         off + 5);
        p.writeUInt32LE(1,         off + 10);
        p.write        (c.name.slice(0, 42), off + 14, 42, 'utf8');
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_ChannelList, p);
}

async function send_AllChannelLists(socket, ctx) {
    const NORMAL_CHANNELS = [
        { type: 1, current: 0, max: 100, name: 'Kanal 1' },
        { type: 1, current: 0, max: 100, name: 'Kanal 2' },
        { type: 1, current: 0, max: 100, name: 'Kanal 3' },
    ];
    const CLAN_CHANNELS = [
        { type: 1, current: 0, max: 100, name: 'Klan Kanalı 1' },
        { type: 1, current: 0, max: 100, name: 'Klan Kanalı 2' },
    ];
    await send_SN_ChannelList(socket, ctx, 'S2',  NORMAL_CHANNELS);
    await send_SN_ChannelList(socket, ctx, 'S2K', CLAN_CHANNELS);
}

// ----- SN_GroupList -----
// sub_100326F0 → entry parser sub_10032240: qmemcpy 0x42 (66 byte) RAW.
//   payload[0]      ?
//   payload[1]      u8 count
//   payload[2..]    count × 66 byte entry (raw blob)
// Saklanan list: *(globalManager + 24) + 604 (= +0x25C).
//
// sub_10052520 lookup zinciri (FULL REVERSE):
//   1. ServerList entry'sini bulur (entry[10..] match)
//   2. ServerList entry[5..] = linkKey alır
//   3. GROUPLIST'te entry[5..] == linkKey olanı arar  ← BU PAKET'İN GİRDİĞİ NOKTA
//   4. Match ise GroupList entry'nin tam 66 byte'ını ServerInfo widget'in
//      output buffer'ına (widget+704) qmemcpy
//   5. ServerInfo display: widget+714 = output[10..] = GroupList entry[10..]
//      → ServerList ekranında "Savaş A." kolonunda görünen yazı BU.
//
// Yani GROUPLIST entry'si:
//   entry[5..]  = LINK KEY (ServerList entry[5..] ile eşleşmeli)
//   entry[10..] = DISPLAY NAME ("Savaş A.", "Klan Maç" vb. — UI'da görünecek)
async function send_SN_GroupList(socket, ctx) {
    const GROUPS = [
        { linkKey: 'GA', displayName: 'Savaş A.' },    // Normal Match Arena
        { linkKey: 'GK', displayName: 'Klan Maç' },    // Clan Match Arena
    ];
    const ENTRY = 66;
    const p = Buffer.alloc(2 + GROUPS.length * ENTRY);
    p[0] = 0;
    p[1] = GROUPS.length;
    let off = 2;
    for (const g of GROUPS) {
        p.write(g.linkKey.slice(0, 4),       off + 5,  4,  'ascii');  // entry[5..8]   = link key
        p.write(g.displayName.slice(0, 32),  off + 10, 32, 'utf8');   // entry[10..41] = UI display
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_GroupList, p);
}

// ----- SN_ItemList -----
// sub_10031000:
//   payload[0]   ?
//   payload[1]   u8 count
//   payload[2..] count × 27 byte entry
// Entry layout (stack reads):
//   off+0   u32 itemId
//   off+4   u32 count/quantity
//   off+8   u8  active flag    → state[+5740]
//   off+9   u32 → state[+3996]
//   off+13  u32 → state[+4000]
//   off+17  u32 → state[+4004]
//   off+21  u16 → state[+4008]
//   off+23  u32 → state[+5544]
async function send_SN_ItemList(socket, ctx) {
    // Entry layout (sub_10148B80 reverse'den):
    //   [0..3] itemIdLOW, [4..7] itemIdHIGH, [8] active u8,
    //   [9..12] creation time u32, [13..16] expiry u32 (state[+4000]),
    //   [17..20] u32, [21..22] u16, [23..26] u32 (state[+5544])
    // Permanent item için expiry = 0x7FFFFFFF (yoksa client "süresi dolmuş" sayar
    // ve sub_101F83D0 inventory.add reddeder → "아이템 생성 실패!" popup).
    const inv = storage.getOrCreateInventory(ctx.username || 'Player');
    const items = inv.items || [];
    const ENTRY = 27;
    const p = Buffer.alloc(2 + items.length * ENTRY);
    p[0] = 0;
    p[1] = items.length;
    const CREATED  = Math.floor(Date.now() / 1000);
    const PERMANENT_EXPIRY = 0x7FFFFFFF;
    let off = 2;
    for (const it of items) {
        p.writeUInt32LE(it.id,             off + 0);
        p.writeUInt32LE(0,                 off + 4);
        p.writeUInt8   (it.active ? 1 : 0, off + 8);
        p.writeUInt32LE(CREATED,           off + 9);
        p.writeUInt32LE(PERMANENT_EXPIRY,  off + 13);
        p.writeUInt32LE(0,                 off + 17);
        p.writeUInt16LE(0,                 off + 21);
        p.writeUInt32LE(PERMANENT_EXPIRY,  off + 23);
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_ItemList, p);
}

// ----- SN_SlotInfo -----
// sub_100312B0: 11 slot, her slot için u32 itemId
// Handler iteration: i = 5..65 step 30, j = 0..11 → reads packet[4*(i+v4)]
//   Slot 1: payload offsets 4..44 (= 11 entries at 4-byte stride)
//   Slot 2: payload offsets 124..164 (= 11 entries at i=35)
// Ancak handler okuma sırası karışık (j → v4 mapping). 11 entry slot başına.
async function send_SN_SlotInfo(socket, ctx) {
    const inv = storage.getOrCreateInventory(ctx.username || 'Player');
    const s = inv.slots || {};
    // Slot 1: 11 u32 — character / weapons / costumes (hangi sıra olduğu kesin değil,
    //   sub_100312B0 j→v4 mapping karışık — şu an default: ilk 7 ana slot, son 4 costume)
    const slot1 = [
        s.character || 0,
        s.character || 0,        // alt karakter
        s.primary   || 0,
        s.primary   || 0,        // alt primary
        s.secondary || 0,
        s.melee     || 0,
        s.grenade   || 0,
        0, 0, 0, 0,              // costume slotları (henüz kullanılmıyor)
    ];
    const p = Buffer.alloc(168);
    let off = 4;
    for (let i = 0; i < slot1.length; i++) {
        p.writeUInt32LE(slot1[i], off);
        off += 4;
    }
    await sendPacket(socket, ctx, PKT.SN_SlotInfo, p);
}

// ----- SN_LockEnd -----
// sub_10032F30: errcode + reason (0,0 = success → ApexMgr.Start)
async function send_SN_LockEnd(socket, ctx) {
    await sendPacket(socket, ctx, PKT.SN_LockEnd, buildErrorAck());
}

// ----- SA_AwayUser -----
// sub_100324C0: errcode + reason + 2 ekstra u32
//   payload[0..1] u16 errcode (must = 0)
//   payload[2..5] u32 reason  (must = 0)
//   payload[6..9] u32 → sub_10051A20 arg1
//   payload[10..13] u32 → sub_10051A20 arg2
async function send_SA_AwayUser(socket, ctx) {
    const p = Buffer.alloc(14);
    // hepsi 0 = success path → CApexMgr cleanup → bağlantı lobby'e devredilir
    await sendPacket(socket, ctx, PKT.SA_AwayUser, p);
}

// ----- SA_HeartbeatAck / SA_KeepAliveAck -----
// Hermit framework-level keep-alive — client parser yok, sadece "alive"
// sinyali. Boş veya minimal payload yeterli.
async function send_SA_HeartbeatAck(socket, ctx) {
    const p = Buffer.alloc(8);
    p.writeUInt32BE(1734441331, 0);
    await sendPacket(socket, ctx, PKT.SA_HeartbeatAck, p);
}

async function send_SA_KeepAliveAck(socket, ctx) {
    const p = Buffer.alloc(4);
    await sendPacket(socket, ctx, PKT.SA_KeepAliveAck, p);
}

// --------------------------------------------------------------------------
// LOGIN BUNDLE
// --------------------------------------------------------------------------

async function sendLoginBundle(socket, ctx) {
    await send_SA_JoyGameLogin(socket, ctx);
    await send_SN_UserInfo    (socket, ctx);
    await send_SN_Record      (socket, ctx);
    await send_SN_RankingInfo (socket, ctx);   // rank position + points
    await send_SN_RecordMapList(socket, ctx);  // boş map record (count=0)
    await send_SN_GroupList   (socket, ctx);
    await send_SN_ServerList  (socket, ctx);
    await send_SN_ServerInfo  (socket, ctx);
    await send_AllChannelLists(socket, ctx);
    await send_SN_ItemList    (socket, ctx);
    await send_SN_SlotInfo    (socket, ctx);
    await send_SN_LockEnd     (socket, ctx);
}

// --------------------------------------------------------------------------
// HANDLER (gelen paket dispatcher'ı)
// --------------------------------------------------------------------------

function readCString(buf, start, max) {
    let end = start;
    while (end < start + max && end < buf.length && buf[end] !== 0) end++;
    return buf.slice(start, end).toString('utf8');
}

// (Eski writeAuthSession kaldırıldı — storage modülü kullanılıyor.)

async function processPacket(socket, dec, ctx) {
    const opcode = dec.readUInt32LE(12);
    const size   = dec.readUInt16LE(6);
    const reqSeq = dec.readUInt16LE(4);

    if (opcode === PKT.CQ_Heartbeat || opcode === PKT.CQ_KeepAlive ||
        opcode === PKT.CQ_KeepAlive2 || opcode === PKT.CQ_KeepAliveAck) {
        ctx.sequence = reqSeq;
    }

    console.log(`[AUTH←${ctx.id.slice(0,6)}] recv 0x${opcode.toString(16)} ${PKT_ALL.NAME(opcode)} (size ${size}, reqSeq ${reqSeq})`);

    try {
        switch (opcode) {

            case PKT.CQ_HackShield:
                break;

            case PKT.CQ_Join:
            case PKT.CQ_JoyGameLogin: {
                // Login payload: nick (33) + password (33) + ip (16)
                const username = readCString(dec, 16,      33);
                const password = readCString(dec, 16 + 33, 33);
                const ipField  = readCString(dec, 16 + 66, 16);

                // Boş username → "No Name Entered"
                if (!username || !username.trim()) {
                    console.log(`[AUTH] login FAIL ip="${ipField}" reason="empty username"`);
                    await send_SA_JoyGameLogin(socket, ctx, LOGIN_ERR.LOGIN_FAILED.errcode, LOGIN_ERR.LOGIN_FAILED.reason);
                    break;
                }

                // Hesap yoksa otomatik kayıt; varsa şifre doğrula.
                const result = storage.loginOrRegister(username, password);
                if (!result.ok) {
                    console.log(`[AUTH] login FAIL user="${username}" ip="${ipField}" reason="${result.reason}"`);
                    // Spesifik hata kodları: sub_10191740 errcode=0x6104 + reason ile
                    // ilgili lokalizasyon string'i popup'ta gösterilir.
                    let err = LOGIN_ERR.LOGIN_FAILED;
                    if (result.reason === 'wrong password') err = LOGIN_ERR.WRONG_PASSWORD;
                    else if (result.reason === 'banned')    err = LOGIN_ERR.ACCOUNT_BANNED;
                    await send_SA_JoyGameLogin(socket, ctx, err.errcode, err.reason);
                    break;
                }

                // Aynı username başka IP'den girmişse: kovmak yerine "Already Logged In" popup
                // (basit duplicate-prevention; gelişmiş session tracking yok).

                ctx.username = username;
                ctx.password = password;
                ctx.userId   = result.userId;
                ctx.loggedIn = true;
                console.log(`[AUTH] login OK user="${username}" ip="${ipField}" userId=${result.userId} ${result.isNew ? '(NEW REGISTRATION)' : '(returning)'}`);

                // Yeni kullanıcıysa default inventory yarat (zaten getOrCreateInventory'de).
                storage.getOrCreateInventory(username);

                // Lobby server'ın CQ_Join handler'ı IP'den nick'i bu dosyadan okur.
                storage.writeUsersSession(socket.remoteAddress, username, result.userId);

                await sendLoginBundle(socket, ctx);
                break;
            }

            case PKT.CQ_AwayUser:
                console.log(`[AUTH] server select for ${ctx.username}`);
                await send_SA_AwayUser(socket, ctx);
                break;

            case PKT.CQ_Heartbeat:
                await send_SA_HeartbeatAck(socket, ctx);
                break;

            case PKT.CQ_KeepAlive:
                await send_SA_KeepAliveAck(socket, ctx);
                break;

            case PKT.CQ_KeepAliveAck:
            case PKT.CQ_KeepAlive2:
            case PKT.CQ_GameInit:
                break;

            default: {
                // Fallback: tanınan paket ID'si için ack-only cevap.
                // Hangar / login alternatifleri / silent paketler — INVALID OPCODE çıkmasın.
                const ackOpcode = helpers.CQ_TO_SA_ACK[opcode] || helpers.CQ_TO_SA_ACK_AUTH[opcode];
                if (ackOpcode) {
                    await sendPacket(socket, ctx, ackOpcode, helpers.buildErrorAck());
                    console.log(`[AUTH] ack-only handler 0x${opcode.toString(16)} → 0x${ackOpcode.toString(16)}`);
                } else if (helpers.SILENT_OPCODES.has(opcode)) {
                    // Sessizce kabul (CN_*/notify paketler)
                } else {
                    console.log(`[AUTH] unknown opcode 0x${opcode.toString(16)} — payload: ${dec.slice(16, Math.min(dec.length, 64)).toString('hex')}`);
                }
            }
        }
    } catch (err) {
        console.error(`[AUTH] handler error 0x${opcode.toString(16)}:`, err.message);
    }
}

function hashStr(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    return h;
}

// --------------------------------------------------------------------------
// SOCKET → PAKET PARÇALAMA + ENCRYPTED MOD AUTO-DETECT
// --------------------------------------------------------------------------

async function onSocketData(socket, data) {
    const ctx = clients.get(socket);
    if (!ctx) return;

    let buffer = ctx.recvBuffer ? Buffer.concat([ctx.recvBuffer, data]) : data;
    ctx.recvBuffer = null;
    if (buffer.length < 16) { ctx.recvBuffer = buffer; return; }

    // Mode tespit (sadece ilk packet için).
    //   1) ENCRYPTED brute-force (CRC32 validation false-positive vermez) — başarılı → ENCRYPTED
    //   2) Aksi → PLAIN size-check (16..0x400 makulse)
    if (ctx.encrypted === null) {
        let keyFound = -1;
        for (let k = 0; k <= 0xFF; k++) {
            if (decryptPacket(buffer.slice(0, Math.min(buffer.length, 0x400)), k)) {
                keyFound = k;
                break;
            }
        }
        if (keyFound >= 0) {
            ctx.encrypted = true;
            ctx.keyByte   = keyFound;
            console.log(`[AUTH ${ctx.id.slice(0,6)}] mode = ENCRYPTED, keyByte=0x${keyFound.toString(16)}`);
        } else {
            const plainSize = buffer.readUInt16LE(6);
            if (plainSize >= 16 && plainSize <= 0x400) {
                ctx.encrypted = false;
                console.log(`[AUTH ${ctx.id.slice(0,6)}] mode = PLAIN`);
            } else {
                console.warn(`[AUTH ${ctx.id.slice(0,6)}] mode tespit edilemedi — bağlantı kapatılıyor`);
                socket.destroy();
                return;
            }
        }
    }

    let off = 0;
    while (off + 16 <= buffer.length) {
        let size, slice;
        if (ctx.encrypted) {
            // Hermit cipher key paketten pakete değişebiliyor (TheRaw.exe sequence-rotation).
            // Cached keyByte'ı önce dene, başarısızsa 0..255 brute-force (lobby'deki aynı mantık).
            const remaining = buffer.slice(off);
            slice = null;
            const cachedSize = peekEncryptedSize(remaining, ctx.keyByte);
            if (cachedSize >= 16 && cachedSize <= 0x400 && off + cachedSize <= buffer.length) {
                const tryDec = decryptPacket(remaining.slice(0, cachedSize), ctx.keyByte);
                if (tryDec) { slice = tryDec; size = cachedSize; }
            }
            if (!slice) {
                for (let k = 0; k <= 0xFF; k++) {
                    if (k === ctx.keyByte) continue;
                    const peekedSize = peekEncryptedSize(remaining, k);
                    if (peekedSize < 16 || peekedSize > 0x400 || off + peekedSize > buffer.length) continue;
                    const tryDec = decryptPacket(remaining.slice(0, peekedSize), k);
                    if (tryDec) { slice = tryDec; size = peekedSize; ctx.keyByte = k; break; }
                }
            }
            if (!slice) {
                if (buffer.length - off >= 0x400) {
                    console.warn(`[AUTH ${ctx.id.slice(0,6)}] decrypt fail @off=${off} bufLen=${buffer.length}`);
                    socket.destroy();
                    return;
                }
                break;   // partial → buffer'da bekle
            }
        } else {
            size = buffer.readUInt16LE(off + 6);
            if (size < 16 || off + size > buffer.length) break;
            slice = buffer.slice(off, off + size);
        }
        await processPacket(socket, slice, ctx);
        off += size;
    }
    if (off < buffer.length) ctx.recvBuffer = buffer.slice(off);
}

// --------------------------------------------------------------------------
// TCP SERVER
// --------------------------------------------------------------------------

const server = net.createServer(socket => {
    const ctx = createClient(socket);
    socket.on('data',  data => onSocketData(socket, data));
    socket.on('close', ()    => destroyClient(socket));
    socket.on('error', err   => {
        console.error(`[AUTH] socket error ${ctx.id.slice(0,6)}: ${err.message}`);
        destroyClient(socket);
    });
});

server.on('error', err => console.error('[AUTH] server error:', err.message));

server.listen(CONFIG.PORT, CONFIG.HOST, () => {
    console.log('=================================');
    console.log(' S2 AUTH SERVER (reverse-verified)');
    console.log(`   listening ${CONFIG.HOST}:${CONFIG.PORT}`);
    console.log(`   lobby     ${CONFIG.LOBBY_HOST}:${CONFIG.LOBBY_PORT}`);
    console.log('=================================');
});
