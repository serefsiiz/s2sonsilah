'use strict';

// ==========================================================================
// S2: Son Silah — LOBBY SERVER (port 13000)
//
// Sorumluluk:
//   - Client lobby join (auth'tan yönlendirilmiş kullanıcı)
//   - Envanter / slot / lock paketleri (auth'tan ayrı, lobby başlangıcında gider)
//   - Hangar / Equipment (envanter ekranı)
//   - Channel: enter / leave / userlist
//   - Room: create / enter / leave / info / userlist / option/map/name/boundary/password
//   - Team: change / exchange / leader
//   - Play: base room info / base user list / ready/start/exit fail / local key
//   - User: state (lobby/room/playing)
//   - Hosting (dedicated): waiting / hostconnect / battle start
//   - TheRawServer.exe DEDICATED handshake: encryption key alır, dedicated context tutar
//   - Heartbeat / keep-alive
//
// State tamamen in-memory. DB yok.
// ==========================================================================

const net  = require('net');
const { v4: uuidv4 } = require('uuid');
const storage = require('../s2_shared/storage');
const items   = require('../s2_shared/items');
const PKT_ALL = require('../s2_shared/packet_ids');
const helpers = require('../s2_shared/packet_helpers');

// CSV tablolarını startup'ta yükle (lazy yerine eager — debug log için)
items.loadItems();
items.loadShop();
items.loadMaps();

// --------------------------------------------------------------------------
// CONFIG
// --------------------------------------------------------------------------

const CONFIG = {
    HOST            : '127.0.0.1',
    PORT            : 13000,           // sex.exe + TheRaw.exe + TheRawServer.exe HEPSI buraya bağlanır
                                       //   - sex.exe       → PLAIN     (CRC sabit 0x117b5a78)
                                       //   - TheRaw.exe    → ENCRYPTED (CRC32 XOR cipher, brute-force key)
                                       //   - TheRawServer  → ENCRYPTED + ilk paket opcode 0x410101
                                       // LaunchServer.bat: -gs_ip 127.0.0.1 -gs_port 13000
    MAX_PACKET_SIZE : 0x400,
    DEDI_PORT       : 27888,           // dedicated server'ın UDP gameplay portu (TheRaw.exe -port 27888)
    DEFAULT_CHANNEL : 1,
};

// --------------------------------------------------------------------------
// PAKET ID'LERİ
// --------------------------------------------------------------------------

const PKT = {
    // ----- gelen -----
    CQ_HackShield               : 0x750101,
    CQ_Join                     : 0x110124,
    CQ_JoyGameLogin             : 0x110111,    // auth login opcode (lobby'ye de gelirse aynı user)
    CQ_EnterUser_Channel        : 0x220111,    // kanal giriş
    CQ_LeaveUser_Channel        : 0x220114,    // kanal çıkış
    CQ_AwayUser                 : 0x220131,
    CQ_Hangar_Open              : 2359553,    // 0x240101
    CQ_Hangar_Close             : 2359555,    // 0x240103
    CQ_Hangar_ChangePart        : 2359559,    // 0x240107
    CQ_Hangar_Unequip           : 2359649,    // 0x240161
    CQ_Hangar_ActiveItem        : 2359585,    // 0x240121 (önceden yanlıştı 0x240141)
    CQ_Hangar_DeleteItem        : 2359587,    // 0x240123
    CQ_Hangar_UseItem           : 2359589,    // 0x240125
    CQ_Hangar_CashBuy           : 2359811,    // 0x240203 (önceden yanlıştı 0x240183)
    CQ_Hangar_Buy               : 2359809,    // 0x240201
    CQ_Room_Create              : 2228737,    // 0x220201
    CQ_Room_EnterUser           : 2228785,    // 0x220231 (eskiden 0x220311 yanlıştı)
    CQ_Room_LeaveUser           : 2228788,    // 0x220234 (eskiden 2228789 yanlıştı — SA ile çakışıyordu)
    NN_Chat_NotBattleAll        : 2229509,    // 0x220505 — oda/lobby chat (iki yönlü)
    NN_Chat_BattleAll           : 0x220509,    // in-game (mid-match) chat — payload: virtualIndex u16 + chat msg + state floats
    NN_Chat_BattleTeam          : 0x220507,    // in-game (mid-match) team-chat — same format as BattleAll
    // CQ_Room_Change* — IDA builder reverse'inden KESİN doğru opcode'lar
    // (sub_1013B330 vd.; eski +1 değerler client'ta tanımsızdı, log'da unknown).
    CQ_Room_ChangeBoundary      : 0x220211,    // 30 byte payload (1 byte data)
    CQ_Room_ChangeOption        : 0x220215,    // 19 byte payload (3 byte data)
    CQ_Room_ChangeName          : 0x220218,    // 74 byte payload (58 byte data)
    CQ_Room_ChangePassword      : 0x22021B,    // 28 byte payload (12 byte data)
    CQ_Room_ChangeMapInfo       : 0x220221,    // 30 byte payload (14 byte data)
    CQ_Team_Change              : 0x220311,    // (eskiden 0x220512 yanlıştı — gerçek opcode NRoom alt-submodule)
    CQ_Team_ExchangeTeam        : 0x220515,
    CQ_Play_Ready               : 0x221F01,
    CQ_Play_Start               : 0x221F03,
    CN_Play_StartButton         : 0x222103,    // Hazır/Start butonu notify (CN, cevap yok)
    CN_Team_Exchange            : 0x220314,    // NRoom auto-balance/team-swap (sub_10136740 builder, 0 byte payload)
    SA_Team_Exchange            : 0x220315,
    SN_Team_Exchange            : 0x220316,
    CN_Chat_DevCommand          : 0x220522,    // dispatcher: tPacket_NMatchup_NChat_CN_DevCommand (CN, cevapsız)
    CQ_TheRawServer_Connect     : 0x410101,    // lobby ←dedi: handshake (43 byte: 27 byte payload — flag/port/IP/serverId)

    // ============================================================
    // dedi → lobby notification opcodes (deep reverse 2026-04-30)
    // ============================================================
    // 0x420203 — dedi → lobby. 16 byte (sadece header, payload yok).
    //            Builder: GameServer.dll sub_100D1FA0 (`mov dword [ecx+0Ch], 420203h; mov [ecx+6], 16`)
    //            Dedi handshake sonrası "ben hazırım" sinyali olarak ilk gelen.
    SN_TheRawServer_HandshakeAck : 0x420203,

    // 0x420205 — dedi → lobby. 18 byte (header + u16 virtualIndex payload).
    //            Builder: 4 farklı yerde (0x10083655/3b32/8553d/85fc3) — user-state notify.
    //            Canlı debug 2026-04-30: state=Playing achieved sinyali (sub_100D28C0
    //            case 2294098 başarıyla tamamlandığında) virtualIndex ile.
    //            Format: payload[0..1] u16 virtualIndex (LE).
    SN_TheRawServer_StatePlaying : 0x420205,

    // 0x420206 — dedi → lobby. 18 byte (header + u16 virtualIndex payload).
    //            Builder: 0x10083685/3b52/847b1. Handshake sonrası 2. notify, virtualIndex ile.
    //            Format: payload[0..1] u16 virtualIndex (LE).
    SN_TheRawServer_HandshakeAck2 : 0x420206,

    // 0x420208 — dedi → lobby. 18 byte (header + u16 virtualIndex payload).
    //            Builder: sub_10083630 (`mov [eax+0Ch], 420208h; mov [eax+6], 18`).
    //            "Notify" — generic per-user event, virtualIndex'le.
    //            Format: payload[0..1] u16 virtualIndex (LE).
    SN_TheRawServer_Notify       : 0x420208,

    // 0x420202 — dedi → lobby. 24 byte. Builder: sub_100D1F80 ve allocator 0x100D2270.
    //            Lobby'den gelen 0x420201'e cevap olarak gönderilir (sub_100D2810 handler).
    //            Format: payload[0..1] u16 virtualIndex=0 + payload[2..5] u32 0
    //                    + payload[6..7] u16 stockMgr field (offset 36).
    SN_TheRawServer_ConnectAck   : 0x420202,

    // 0x420209 — dedi → lobby. 18 byte. Builder: sub_100D1FE0 ve allocator 0x100D22C0.
    SN_TheRawServer_Notify2      : 0x420209,

    // ============================================================
    // lobby → dedi command opcodes (sub_100D2810 dispatcher)
    // ============================================================
    // 0x420201 — lobby → dedi: "begin/connect" cmd. dedi 0x420202 ile cevap verir.
    // 0x420207 — lobby → dedi: ?? cmd. Dedi user lookup yapar, başarılıysa "SN_NotExistUser" log.
    // 0x420320 — lobby → dedi: "UserExit" cmd. Dedi user lookup yapar, başarılıysa "SN_UserExit" log.
    CN_DEDI_UserExit             : 0x420320,

    // ============================================================
    // dedi engine → lobby: spawn task notify (DoRespawn)
    // ============================================================
    // 0x230103 — dedi → lobby. 19 byte. Builder: sub_100CC270 (DoRespawn).
    //            Engine task queue'ya enqueue edildiğinde lobby'ye broadcast'lanıyor.
    //            Format: payload[0..1] u16 virtualIndex (LE)
    //                    payload[2]    u8  doRespawnFlag (DoRespawn 2. argümanı; 0 normal spawn)
    //            Reverse (sub_100CC270 disasm onaylı): packet[0xC]=0x230103, packet[6]=19,
    //            packet[0x10]=virtualIndex, packet[0x12]=flag.
    SN_TheRawServer_DoRespawnTask : 0x230103,

    // 0x230111 — dedi → lobby. 16 byte (sadece header, payload yok).
    //            Builder: sub_100CBDC0 + 0x100CC012 + 0x100CC223 (sub_100CD7D0 içinde).
    //            Reverse: sub_100CD7D0 — round bitiş state geçişi (state=5=EndingRound).
    //            Non-host mode'da (`[global+108] != 1`) round bitince enqueue ediliyor.
    //            "Host EServerGameState_EndingRound" debug string'i ile bağlantılı.
    SN_TheRawServer_RoundEnd      : 0x230111,

    // 0x230151 — dedi case 2294097 (sub_10058CC0) — per-user spawn handler.
    //            Format: payload[0..1] u16 virtualIndex
    SN_RoundStart                 : 0x230151,
    SN_Battle_Captin              : 0x230151,    // backward-compat alias

    // ----- D187 maç-içi opcode'lar (2026-04-30 MITM capture) -----
    // DOĞRU isimler (kullanıcı düzeltmesi): bunlar GAME EVENT'leri, periodic heartbeat değil!
    SN_Game_Revive                : 0x230104,    // SN_Revive — birinin revive olduğu notify
    SN_Game_Kill                  : 0x230124,    // SN_Kill — kill bildirimi (her kill için 1 paket)
    NN_Match_BattleTeamRadio      : 0x220510,    // takım radio chat (V-W-X tuşlarıyla bağırma)
    CN_Play_Ping                  : 0x222141,    // Client→Server periodic ping (24B, 8B payload)
    SA_Play_Ping                  : 0x222142,    // Server→Client ping ack (46B)
    SN_Play_PingExtra             : 0x222143,    // Server→Client ping ack-2 (22B zeros)

    // BACKWARD-COMPATIBILITY aliases (eski karışık isimler — yeni kod yukarıdaki
    // doğru isimleri kullanmalı, eski case'ler lobby kodunda hala bunlara bakıyor).
    CN_TheRawServer_Ready1        : 0x420203,    // = SN_TheRawServer_HandshakeAck
    CN_TheRawServer_Ready2        : 0x420205,    // = SN_TheRawServer_StatePlaying (eski 0x420206 yanlıştı)
    CN_TheRawServer_Ready3        : 0x420206,    // = SN_TheRawServer_HandshakeAck2 (eski 0x420204 yanlıştı)
    CN_TheRawServer_Notify        : 0x420208,    // = SN_TheRawServer_Notify
    CN_TheRawServer_ClientAdded   : 0x420105,    // ⚠ DEDI BINARY'DE BU OPCODE YOK — case fire etmiyor
    CQ_Heartbeat                : 0x20080,
    CQ_KeepAlive                : 0x20082,
    CQ_KeepAliveAck             : 0x20083,
    CQ_KeepAlive2               : 0x20084,    // 24 byte (16 header + 8 payload)
                                                //   GameServer.dll sub_100E5280 builder, sub_100F2AF0 handler
    SA_KeepAlive2Ack            : 0x20085,    // 18 byte (16 header + 2 byte BE u16 payload)
                                                //   GameServer.dll sub_100F13E0 builder, sub_100F17D0 sender
    CQ_KeepAlive2Status         : 0x20086,    // 18 byte (sub_100F2AF0 conditional sender)

    // ----- giden -----
    SA_Join                     : 0x110125,
    SA_JoyGameLogin             : 0x110112,    // 1114386 (switch tablosundan teyit)
    SN_ItemList                 : 0x210111,
    SN_SlotInfo                 : 0x210113,
    SN_LockEnd                  : 0x210121,
    SN_GroupList                : 0x220107,    // sub_100326F0 — group/region (66-byte entry)
    SN_ChannelList              : 0x220102,    // sub_100742C0 — channel list (57-byte entry)
    SA_EnterUser_Channel        : 0x220112,
    SA_LeaveUser_Channel        : 0x220115,
    SN_LeaveUser_Channel        : 0x220116,
    SN_UserList_Channel         : 0x220113,
    SA_AwayUser                 : 0x220132,
    SA_Hangar_Open              : 2359554,    // 0x240102
    SA_Hangar_Close             : 2359556,    // 0x240104
    SA_Hangar_ChangePart        : 2359560,    // 0x240108
    SA_Hangar_Unequip           : 2359650,    // 0x240162
    SA_Hangar_ActiveItem        : 2359586,    // 0x240122
    SA_Hangar_DeleteItem        : 2359588,    // 0x240124
    SA_Hangar_UseItem           : 2359590,    // 0x240126
    SA_Hangar_CashBuy           : 2359812,    // 0x240204
    SA_Hangar_Buy               : 2359810,    // 0x240202
    SA_Room_Create              : 2228738,    // 0x220202
    SN_Room_Info                : 2228739,    // 0x220203
    SN_Room_UpdateInfoToChannel : 2228740,    // 0x220204
    SA_Room_EnterUser           : 2228786,    // 0x220232 (eskiden 0x220312 yanlıştı)
    SA_Room_LeaveUser           : 2228789,    // 0x220235
    SN_Room_LeaveUser           : 2228790,    // 0x220236 (eskiden 0x220316 yanlıştı)
    SN_Room_UserList            : 2228787,    // 0x220233
    SN_Room_ChangeMapInfo       : 2228771,    // 0x220223
    SA_Room_ChangeMapInfo       : 2228770,    // 0x220222
    SN_Room_ChangeBoundary      : 2228755,    // 0x220213
    SA_Room_ChangeBoundary      : 2228754,    // 0x220212
    SN_Room_ChangeName          : 2228762,    // 0x22021A
    SA_Room_ChangeName          : 2228761,    // 0x220219
    SN_Room_ChangeOption        : 2228759,    // 0x220217
    SA_Room_ChangeOption        : 2228758,    // 0x220216
    SA_Room_ChangePassword      : 2228764,    // 0x22021C
    SN_Room_ChangeRoomState     : 2228756,    // 0x220214
    SN_Room_ChangeLeader        : 2229017,    // 0x220319 (sub_1013BC20'dan teyit)
    SN_Room_UserColorNickInfo   : 2228793,    // 0x220239 (eskiden ChangeLeader ile çakışıyordu)
    SA_Room_CompulsionAway      : 2228792,    // 0x220238 (eskiden 0x220318 yanlıştı)
    SA_Team_Change              : 0x220312,    // (eskiden 0x220512 yanlıştı)
    SN_Team_Change              : 0x220313,    // (eskiden 0x220513 yanlıştı)
    SA_Team_ExchangeTeam        : 0x220515,
    SN_Team_ExchangeTeam        : 0x220516,
    SN_Team_ChangeLeader        : 0x220519,
    SN_Play_BaseRoomInfo        : 2236689,    // 0x222111
    SN_Play_BaseUserList        : 2236690,    // 0x222112
    SN_Play_BattleInfo          : 2236692,    // 0x222114 — eski emülatörde createRoom akışında dahil
    SN_Result_GameFinalResult   : 2236961,    // 0x222221 — match-end Result ekranı per-player 811 byte
    SN_Play_ReadyButtonFail     : 2236674,    // 0x222102
    SN_Play_StartButtonFail     : 2236676,    // 0x222104
    SN_Play_LocalKey            : 2236677,    // 0x222105
    SN_Play_ExitButton          : 2236722,    // 0x222132
    SN_User_State               : 2229249,    // 0x220401
    SN_Hosting_Waiting          : 4326145,    // 0x420301
    SN_Hosting_HostingFail      : 4326146,    // 0x420302
    SN_Hosting_HostConnect      : 4326147,    // 0x420303
    SN_Hosting_BattleStart      : 4326160,    // 0x420310
    SN_Chat_DevCommandFail      : 0x220523,    // dispatcher: tPacket_NMatchup_NChat_SN_DevCommandFail
    SN_PackageItem              : 0x240131,    // 2359601 — sub_10148B80 "item envantere eklendi" push
    SA_HeartbeatAck             : 0x20081,
    SA_KeepAliveAck             : 0x20083,
};

// --------------------------------------------------------------------------
// HERMIT ENCRYPTION (CRC32 XOR cipher)
// --------------------------------------------------------------------------
// Reverse: gg.dll (TheRaw.exe'nin DLL formu), Hermit::Object::Crypt::CRC ve
// Hermit::Session::Cipher::TCP sınıfları. Algoritma eski lobby server/sex.js'ten
// port edildi.
//
// Cipher: byte_out[i] = keyByte XOR orig[i] XOR (crcTable[i] & 0xFF)  (i = 4..size)
// Symmetric: aynı fonksiyon hem encrypt hem decrypt yapar (XOR cipher).
// CRC: CRC32 (poly 0xEDB88320), packet[0..3] BE u32, packet[4..size] üzerinden.
// Header: encrypted modda BE; plain modda (sex.exe) sabit CRC 0x117b5a78 LE.
//
// Mode tespiti: ilk packet'in [0..3] LE u32 == 0x117b5a78 ise PLAIN; aksi halde
// ENCRYPTED, keyByte brute-force ile bulunur (default 0x0F).

const crcTable = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        t[n] = c >>> 0;
    }
    return t;
})();

// Encrypt: LE-header packet → BE-header + XOR cipher + CRC32
// (in-place değil, yeni Buffer döner; size = buf[6..7] LE'den okunur)
function cryptPacket(buf, keyByte, sequence) {
    const size = buf.readUInt16LE(6);
    const out  = Buffer.alloc(size);
    buf.copy(out, 0, 0, size);
    // Header: LE → BE swap (sequence, size, opcode)
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

// Decrypt: BE-header encrypted packet → LE-header plain. NULL döner CRC fail'de.
// Network'ten gelen encrypted byte'lar üzerinden CRC hesaplanır (sex.js mantığı).
function decryptPacket(buf, keyByte) {
    if (buf.length < 16) return null;
    const out = Buffer.from(buf);
    let crc = 0xFFFFFFFF;

    // Header (4..16) decrypt + CRC update (orig=encrypted byte üzerinden)
    for (let i = 4; i < 16; i++) {
        const orig = buf[i];
        out[i] = keyByte ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    // Header field'ları BE → LE byte-swap (sequence, size, opcode)
    out.slice(4,  6).swap16();
    out.slice(6,  8).swap16();
    out.slice(12, 16).swap32();

    const size = out.readUInt16LE(6);
    if (size < 16 || size > buf.length || size > 0x400) return null;

    // Payload (16..size) decrypt + CRC
    for (let i = 16; i < size; i++) {
        const orig = buf[i];
        out[i] = keyByte ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }

    // CRC validate: stored @ packet[0..3] BE u32 vs ~crc
    const stored     = buf.readUInt32BE(0);
    const calculated = (~crc) >>> 0;
    if (calculated !== stored) return null;

    return out;
}

// Plain header builder (sex.exe modu için).
function buildPacketPlain(sequence, opcode, payload) {
    const payloadLen = payload ? payload.length : 0;
    const size = 16 + payloadLen;
    const buf  = Buffer.alloc(size);
    buf.writeUInt32LE(0x117b5a78, 0);   // sabit CRC (plain'de validation yok)
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
            const seq = ctx.sequence++;
            const plain = buildPacketPlain(seq, opcode, payload);
            const wire  = ctx.encrypted ? cryptPacket(plain, ctx.keyByte, seq) : plain;
            socket.write(wire, err => err ? reject(err) : resolve());
            const tag = ctx.encrypted ? 'ENC' : 'plain';
            console.log(`[LOBBY→${ctx.id.slice(0,6)}] sent 0x${opcode.toString(16)} ${PKT_ALL.NAME(opcode)} (${payload ? payload.length : 0} byte, seq ${seq}, ${tag})`);
        } catch (err) { reject(err); }
    });
}

// --------------------------------------------------------------------------
// IN-MEMORY STATE
// --------------------------------------------------------------------------

const clients     = new Map();   // socket → ctx
const channels    = new Map();   // channelId → { id, name, sockets: Set }
const rooms       = new Map();   // roomId → room obj
const dedicateds  = new Map();   // socket → { id, ip, port, key, roomId }
let   nextRoomId  = 1;

// default kanalları başlat
channels.set(1, { id: 1, name: 'Kanal 1', sockets: new Set() });
channels.set(2, { id: 2, name: 'Kanal 2', sockets: new Set() });

function createClient(socket) {
    const ctx = {
        id          : uuidv4(),
        sequence    : 1,         // per-client sayaç, 1'den başlar
        // encryption: ilk packet geldiğinde tespit (PLAIN: sabit CRC 0x117b5a78,
        // ENCRYPTED: brute-force keyByte). null = henüz bilinmiyor.
        encrypted   : null,
        keyByte     : 0x0F,      // default — encrypted ise tespit edildiğinde override
        recvBuffer  : null,      // partial packet buffer
        userId      : 0,
        username    : null,
        channelId   : null,
        roomId      : null,
        team        : 0,
        slot        : 0,
        ready       : false,
        isDedicated : false,
    };
    clients.set(socket, ctx);
    console.log(`[LOBBY] client connected: ${ctx.id.slice(0,6)} from ${socket.remoteAddress}`);
    return ctx;
}

function destroyClient(socket) {
    const ctx = clients.get(socket);
    if (!ctx) return;

    // odadaysa odadan çıkar
    if (ctx.roomId) leaveRoom(socket, ctx).catch(() => {});

    // kanaldaysa kanaldan çıkar
    if (ctx.channelId) {
        const ch = channels.get(ctx.channelId);
        if (ch) ch.sockets.delete(socket);
    }

    // dedicated context varsa kaldır
    if (dedicateds.has(socket)) {
        const d = dedicateds.get(socket);
        console.log(`[LOBBY] dedicated server disconnected: room=${d.roomId}`);
        dedicateds.delete(socket);
    }

    console.log(`[LOBBY] client disconnected: ${ctx.id.slice(0,6)}`);
    clients.delete(socket);
}

function findSocketByUserId(userId) {
    for (const [s, c] of clients) if (c.userId === userId) return s;
    return null;
}

// --------------------------------------------------------------------------
// HELPERS
// --------------------------------------------------------------------------

function readCString(buf, start, max) {
    let end = start;
    while (end < start + max && end < buf.length && buf[end] !== 0) end++;
    return buf.slice(start, end).toString('utf8');
}

function writeOkHeader(buf) {
    buf.writeUInt16LE(0, 0);
    buf.writeUInt32LE(0, 2);
}

function hashStr(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    return h;
}

// IP-based session lookup artık storage modülünde
// (auth login sonrası _session/users.json içine yazılır).
function lookupAuthSession(ip) {
    const entry = storage.lookupUserByIp(ip);
    if (!entry) return null;
    // 10 dakikadan eski oturumları kabul etme
    if (Date.now() - (entry.ts || 0) > 10 * 60 * 1000) return null;
    return entry;
}

// Kanaldaki tüm soketlere paket gönder (dedicated hariç)
async function broadcastChannel(channelId, opcode, payload, exceptSocket = null) {
    const ch = channels.get(channelId);
    if (!ch) return;
    const ps = [];
    for (const s of ch.sockets) {
        if (s === exceptSocket) continue;
        const c = clients.get(s);
        if (c && !c.isDedicated) ps.push(sendPacket(s, c, opcode, payload).catch(() => {}));
    }
    await Promise.all(ps);
}

// Odadaki tüm oyunculara paket gönder
async function broadcastRoom(roomId, opcode, payload, exceptSocket = null) {
    const room = rooms.get(roomId);
    if (!room) return;
    const ps = [];
    for (const [, p] of room.players) {
        if (p.socket === exceptSocket) continue;
        const c = clients.get(p.socket);
        if (c) ps.push(sendPacket(p.socket, c, opcode, payload).catch(() => {}));
    }
    await Promise.all(ps);
}

// --------------------------------------------------------------------------
// PAKET BUILDER'LAR — LOGIN + ENVANTER
// --------------------------------------------------------------------------

// SA_Join: lobby giriş onayı.
// GameClient.dll sub_10030C90 parser sadece errcode (u16 @ payload[0]) +
// reason (u32 @ payload[2]) okuyor; her ikisi 0 = başarılı.
// ÖNCEKI BUG: 52-byte payload'da `writeUInt16LE(serverCount, 1)` errcode'un
// ikinci byte'ını eziyordu → errcode = 256 → "recv SA_Join failed!" log +
// PopUpIdentify.status hata popup'ı.
async function send_SA_Join(socket, ctx) {
    const p = Buffer.alloc(6);
    p.writeUInt16LE(0, 0);   // errcode = 0
    p.writeUInt32LE(0, 2);   // reason  = 0
    await sendPacket(socket, ctx, PKT.SA_Join, p);
}

// SN_GroupList — group/region listesi (UI'da "Savaş A." kolonu).
// Auth da gönderdi ama lobby disconnect/reconnect sonrası tekrar göndermek gerek
// (parser sub_100326F0 yeni geldiğinde mevcut listeyi siliyor → re-send şart).
async function send_SN_GroupList(socket, ctx) {
    const GROUPS = [{ key: 'S2', displayName: 'S2' }];
    const ENTRY = 66;
    const p = Buffer.alloc(2 + GROUPS.length * ENTRY);
    p[0] = 0;
    p[1] = GROUPS.length;
    let off = 2;
    for (const g of GROUPS) {
        p.write(g.key.slice(0, 4),          off + 5,  4,  'ascii');
        p.write(g.displayName.slice(0, 32), off + 10, 32, 'utf8');
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_GroupList, p);
}

// SN_ChannelList — kanal listesi.
// KRİTİK: payload[2..]'de SERVER KEY string LOOKUP yapılıyor (sub_100743A0).
// Bu key SN_ServerInfo entry[0..4] (server short ID) ile match etmeli yoksa
// parser HİÇ çağrılmaz → channel list boş kalır.
// 57-byte entry: u8 type, u16 current, u16 max, u8 flag, 4b unused,
// u32 active flag, char[43] channel name.
async function send_SN_ChannelList(socket, ctx, serverKey, channels) {
    const ENTRY = 57;
    const HEADER = 7;
    const p = Buffer.alloc(HEADER + channels.length * ENTRY);
    p[0] = 0;
    p[1] = channels.length;
    p.write(serverKey.slice(0, 4), 2, 4, 'ascii');
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

// SN_ItemList — inventory.json'dan üretilir. Format auth ile aynı:
//   Entry: u32 itemIdLow + u32 itemIdHigh + u8 active + state fields
// Önemli: state[+4000] = expiry → 0 ise client item'ı süresi dolmuş sayar.
// Permanent için 0x7FFFFFFF (max signed u32) kullanıyoruz.
async function send_SN_ItemList(socket, ctx) {
    const inv = storage.getOrCreateInventory(ctx.username || 'Player');
    const items = inv.items || [];
    const ENTRY = 27;
    const p = Buffer.alloc(2 + items.length * ENTRY);
    p[0] = 0;
    p[1] = items.length;
    const NOW = Math.floor(Date.now() / 1000);
    const PERMANENT_EXPIRY = 0x7FFFFFFF;
    let off = 2;
    for (const it of items) {
        const created = it.created || NOW;
        const expiry  = (it.expiry && it.expiry > 0) ? it.expiry : PERMANENT_EXPIRY;
        p.writeUInt32LE(it.id,             off + 0);    // itemId LOW
        p.writeUInt32LE(0,                 off + 4);    // itemId HIGH
        p.writeUInt8   (it.active ? 1 : 0, off + 8);    // active
        p.writeUInt32LE(created,           off + 9);    // creation time
        p.writeUInt32LE(expiry,            off + 13);   // expiry
        p.writeUInt32LE(0,                 off + 17);
        p.writeUInt16LE(0,                 off + 21);
        p.writeUInt32LE(expiry,            off + 23);
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_ItemList, p);
}

// SN_SlotInfo — sub_100312B0 reverse (KESIN offset mapping):
//
// İki slot seti (i=5 ve i=35), her set 11 slot.
// `sprintf("%d%02d", wireValue, 0)` ile wire değerini 100x yapıp lookup ediyor.
// Slot index → wire byte offset (parser switch'ten):
//   payload[ 4] = j=5  → CHARACTER (Body)        (i=5,  v4=0 → a1+20)
//   payload[ 8] = j=1  → primary weapon          (i=5,  v4=1 → a1+24)
//   payload[12] = j=2  → secondary weapon        (i=5,  v4=2 → a1+28)
//   payload[16] = j=3  → melee                   (i=5,  v4=3 → a1+32)
//   payload[20] = j=4  → grenade                 (i=5,  v4=4 → a1+36)
//   payload[24] = j=6  → costume slot a (head)   (i=5,  v4=5)
//   payload[28] = j=9  → costume slot b (body)   (i=5,  v4=6)
//   payload[32] = j=10 → costume slot c          (i=5,  v4=7)
//   payload[36] = j=7  → costume slot d (back)   (i=5,  v4=8)
//   payload[40] = j=8  → costume slot e          (i=5,  v4=9)
//   payload[44] = j=11 → costume slot f          (i=5,  v4=10)
//   payload[124..164] = aynı sırayla SLOT SET #2 (loadout 2)
// Min payload = 168 byte (her iki set + sonraki padding).
async function send_SN_SlotInfo(socket, ctx) {
    const inv = storage.getOrCreateInventory(ctx.username || 'Player');
    const s = inv.slots || {};
    const p = Buffer.alloc(168);
    function writeSet(baseOff) {
        p.writeUInt32LE(s.character    || 0, baseOff +  0);   // j=5  Body
        p.writeUInt32LE(s.primary      || 0, baseOff +  4);   // j=1
        p.writeUInt32LE(s.secondary    || 0, baseOff +  8);   // j=2
        p.writeUInt32LE(s.melee        || 0, baseOff + 12);   // j=3
        p.writeUInt32LE(s.grenade      || 0, baseOff + 16);   // j=4
        p.writeUInt32LE(s.costumeHead  || 0, baseOff + 20);   // j=6
        p.writeUInt32LE(s.costumeBody  || 0, baseOff + 24);   // j=9
        p.writeUInt32LE(s.costumeBack  || 0, baseOff + 28);   // j=10
        p.writeUInt32LE(s.costumeExtra1|| 0, baseOff + 32);   // j=7
        p.writeUInt32LE(s.costumeExtra2|| 0, baseOff + 36);   // j=8
        p.writeUInt32LE(s.costumeExtra3|| 0, baseOff + 40);   // j=11
    }
    writeSet(4);     // slot set #1 — payload[4..47]
    writeSet(124);   // slot set #2 — payload[124..167]
    await sendPacket(socket, ctx, PKT.SN_SlotInfo, p);
}

async function send_SN_LockEnd(socket, ctx) {
    // "Login bundle bitti, UI'yi kilitten çıkar" sinyali.
    const p = Buffer.alloc(8);
    writeOkHeader(p);
    await sendPacket(socket, ctx, PKT.SN_LockEnd, p);
}

// SN_Messenger_FriendList — boş friend list (UI "no friends" gösterir)
async function send_SN_FriendList(socket, ctx) {
    await sendPacket(socket, ctx, PKT_ALL.SN_Messenger_FriendList, helpers.buildEmptyList());
}

// SN_Mail_Info / SN_MailGift_Info — boş mail/hediye sayacı
async function send_SN_MailInfo(socket, ctx) {
    const p = Buffer.alloc(8);   // u32 totalCount + u32 unreadCount = 0/0
    await sendPacket(socket, ctx, PKT_ALL.SN_Mail_Info, p);
}
async function send_SN_MailGiftInfo(socket, ctx) {
    const p = Buffer.alloc(8);
    await sendPacket(socket, ctx, PKT_ALL.SN_MailGift_Info, p);
}

// SN_Achievement_BaseInfo — boş achievement (UI "no achievements yet")
async function send_SN_AchievementBaseInfo(socket, ctx) {
    await sendPacket(socket, ctx, PKT_ALL.SN_Achievement_BaseInfo, helpers.buildEmptyList());
}

// SN_Guild_NotClanner — kullanıcı klan üyesi değil bilgisi
async function send_SN_GuildNotClanner(socket, ctx) {
    await sendPacket(socket, ctx, PKT_ALL.SN_Guild_NotClanner, helpers.buildErrorAck());
}

// SN_UserInfo — auth'tan bağımsız olarak lobby de güncellemek için.
// Format auth'la aynı: 25 byte nick + 25 byte clan name (null-terminated, padding sıfır).
async function send_SN_UserInfo(socket, ctx) {
    const NICK_LEN = 25;
    const CLAN_LEN = 25;
    const p = Buffer.alloc(NICK_LEN + CLAN_LEN);
    const nick = (ctx.username || 'Player').slice(0, NICK_LEN - 1);
    p.write(nick, 0, NICK_LEN - 1, 'utf8');
    const clan = ctx.username ? storage.getClan(ctx.username) : null;
    if (clan && clan.name) {
        p.write(clan.name.slice(0, CLAN_LEN - 1), NICK_LEN, CLAN_LEN - 1, 'utf8');
    }
    await sendPacket(socket, ctx, PKT_ALL.SN_UserInfo, p);
}

async function sendLobbyEntryBundle(socket, ctx) {
    await send_SA_Join       (socket, ctx);
    await send_SN_UserInfo   (socket, ctx);   // güncel nick+clan (auth'tan sonra refresh)
    await send_SN_GroupList  (socket, ctx);   // group ("Savaş A." kolonu için)
    await send_AllChannelLists(socket, ctx);  // her server için ayrı SN_ChannelList
    await send_SN_ItemList   (socket, ctx);
    await send_SN_SlotInfo   (socket, ctx);
    await send_SN_FriendList(socket, ctx);    // boş friend list
    await send_SN_MailInfo  (socket, ctx);    // 0 mail
    await send_SN_MailGiftInfo(socket, ctx);  // 0 hediye
    await send_SN_AchievementBaseInfo(socket, ctx);  // boş achievement
    // Sadece klanı yoksa NotClanner gönder; aksi halde klan ekranı açık kalır.
    const clan = ctx.username ? storage.getClan(ctx.username) : null;
    if (!clan || !clan.name) {
        await send_SN_GuildNotClanner(socket, ctx);
    }
    await send_SN_LockEnd    (socket, ctx);
}

// --------------------------------------------------------------------------
// PAKET BUILDER'LAR — CHANNEL
// --------------------------------------------------------------------------

// SA_EnterUser (Channel Select cevabı). Format kullanıcının çalışan kodundan port.
async function send_SA_EnterUser_Channel(socket, ctx) {
    const p = Buffer.alloc(512);
    let off = 1;
    const serverCount = 2;

    p.writeUInt16LE(serverCount, off);
    off += 6;
    for (let i = 0; i < serverCount; i++) {
        off += 4;
        p[off++] = 0x00;
        off += p.write(`127.0.0.${i + 1}`, off, 'utf8');
        p[off++] = 0x00;
        p.writeUInt16LE(12000, off);
        off += 2;
        off += 4;
        off += p.write(`Server ${i + 1}`, off, 'utf8');
        p[off++] = 0x00;
        off += 68;
    }

    await sendPacket(socket, ctx, PKT.SA_EnterUser_Channel, p.slice(0, off));
}

async function send_SN_UserList_Channel(socket, ctx) {
    const ch = channels.get(ctx.channelId);
    if (!ch) return;

    const p = Buffer.alloc(512);
    p.fill(0);
    writeOkHeader(p);

    let off = 6;
    p.writeUInt16LE(ch.sockets.size, off); off += 2;

    for (const s of ch.sockets) {
        const c = clients.get(s);
        if (!c) continue;
        p.writeUInt32LE(c.userId, off); off += 4;
        p.write((c.username || '').slice(0, 31), off, 31, 'utf8'); off += 32;
        p.writeUInt16LE(50, off); off += 2;     // level
        p.writeUInt8(1, off);     off += 1;     // status
    }

    await sendPacket(socket, ctx, PKT.SN_UserList_Channel, p.slice(0, off));
}

// --------------------------------------------------------------------------
// PAKET BUILDER'LAR — ROOM
// --------------------------------------------------------------------------

// SN_Room_Info payload formatı.
// Reverse: CDispatch_NMatchup_NRoom_SN_Info::Dispatch (sub_101393A0) +
//          parser sub_10072640 + alt struct parser sub_10072530.
//
// Layout (en az 215 byte = 0xD7, Dispatch sonunda full memcpy backup):
//   [0..1]    u16    err code (0)
//   [2..5]    u32    err reason (0)
//   [6]       u8     room state  (2/3=create akışı, 5=in-game, 6=özel result)
//   [9]       u8     this[0] flag
//   [10]      u8     this[1] flag
//   [14..43]  utf8   room name (null-term, ~30 byte alan)
//   [25..28]  4×u8   maxPlayers, currentPlayers, gameMode, gameType
//   [29..88]  60 B   sub-struct (sub_10072530 — boundary/team/round config alt parser)
//   [90..91]  u16    field A → game state +48 (round count?)
//   [92..93]  u16    field B → game state +49 (time limit?)
//   [94..95]  u16    field C → game state +50 (boundary?)
//   [96..101] 3×u16  ek game config
//   [185]     u8     this[60] flag (friendly fire?)
//   [186]     u8     this[72] flag (auto balance?)
//   [187..190] u32   id A (mapId?)
//   [191..194] u32   id B (roomId?)
//   [195..198] u32   state=6 için özel field
function buildRoomInfoPayload(room) {
    const p = Buffer.alloc(215);                       // 0xD7
    p.fill(0);

    // CQ_Create echo benzeri başlık (client'in tanıdığı format):
    //   payload[0]   = roomType
    //   payload[1]   = 0x10 statik
    //   payload[2]   = mapID u8 ← UI map name lookup için
    //   payload[3]   = 0x27 statik (room name max len)
    p.writeUInt8  (room.type || 1,         0);
    p.writeUInt8  (0x10,                   1);
    p.writeUInt8  ((room.mapId || 10015) & 0xFF, 2);   // mapId LOW byte (UI hint)
    p.writeUInt8  (0x27,                   3);

    // err code/reason — bazı pakeltler bunu offset 0..5'te bekler, ama biz CQ-style header'ı
    // kullanıyoruz; success durumu için payload[0..3] zaten geçerli, ek alan yok.

    // Room state — Dispatch switch ile UI scene seçer (sub_101393A0 a1+22 = payload[6])
    const state = room.status === 'playing' ? 5 : 2;
    p.writeUInt8  (state,                  6);

    // payload[7..8] u16 = HOST USER ID (LOW 16 bit).
    // Reverse: sub_10072640 sonunda qmemcpy(substate+73, packet, 0xD7) → tüm packet
    // substate'in sonuna kopyalanır → substate[+0x60] = packet[+23] = payload[+7].
    // Squad render (sub_1013DD80) `[substate+0x60]` u16'yı her player.userId LOW 16 ile
    // karşılaştırıp eşleşen satıra "master" badge yazar (aMaster string).
    p.writeUInt16LE(room.hostUserId & 0xFFFF, 7);

    p.writeUInt8  (room.type || 1,         9);
    // payload[10] >> 1 = aktif squad slot sayısı (her takım için).
    // sub_1013B4D0 [n..7] arası slotları "GameRoomList.disabledASquadListAt" ile DISABLE eder.
    // 0 yazarsak 8 slot da disable → squad list boş görünür. maxPlayers (genelde 16) → 8 aktif.
    p.writeUInt8  (room.maxPlayers,       10);

    // Room name (UTF-8, null-terminated, max 30 byte) — sub_10072640 a2+30 = payload[14]
    p.write(room.name.slice(0, 30),       14, 30, 'utf8');

    // 4 byte config block
    p.writeUInt8  (room.maxPlayers,       25);
    p.writeUInt8  (room.players.size,     26);
    p.writeUInt8  (room.gameMode || 1,    27);
    p.writeUInt8  (room.gameType || 1,    28);

    // payload[90..95] = TAKIM ID'LERİ (state+48/+49/+50)
    // sub_100720C0 UserList parser'ında entry.team bu 3 id'den BİRİYLE eşleşmek zorunda;
    // eşleşmezse client "Missing nTeamIndex error!" MessageBox atıyor.
    // Standart: 1=red, 2=blue, 0=spectator/none.
    p.writeUInt16LE(1, 90);     // nTeamIndex1 (red team id)
    p.writeUInt16LE(2, 92);     // nTeamIndex2 (blue team id)
    p.writeUInt16LE(0, 94);     // nTeamIndex3 (spectator/none)
    // payload[96..101] hâlâ tahmin — round/time/boundary buralarda olabilir
    p.writeUInt16LE(room.roundCount || 10,  96);
    p.writeUInt16LE(room.timeLimit  || 180, 98);
    p.writeUInt16LE(room.boundary   || 0,  100);

    // ============================================================
    // KRİTİK MAP ARRAY (sub_1006FB20 reverse'inden)
    // ------------------------------------------------------------
    // sub_1006FB20(state, a2): if (a2<6) return state+195+13*a2; else NULL;
    //
    // Yani roomData içinde MAX 6 map slotluk array var, her struct 13 byte.
    // qmemcpy(state+73, packet, 0xD7) → state+195 = packet+(195-73) = packet+122
    //                                 = payload[122-16] = payload[106]
    //
    // Layout:
    //   payload[102]      = u8 SELECTED MAP INDEX (0..5)
    //   payload[106..183] = 6 × 13 byte MAP STRUCT
    //     struct[0..1]    = u16 mapId (Map.csv INDEX: 10007/10015/...)
    //     struct[2..12]   = 11 byte (rule/setting/flag — tahmin)
    //
    // sub_10140AE0/sub_10140450 (UI updater) struct'ın ilk u16'sını mapId olarak
    // okur, Scaleform'a updateGameRoomName/updateGameRoomInfo ile yollar.
    // ============================================================

    // Selected map = slot 0 → buildMapSlots() room.mapId'i hep slot 0'a koyuyor.
    // Bu sayede client farklı map seçtiğinde hep "0. slot" UI'da görünüyor.
    p.writeUInt8(0, 102);

    // MAP_SLOTS — gerçek Map.csv'den dinamik (selected mapId hep slot 0).
    // Diğer 5 slot popüler map'lerle dolduruluyor (UI map menu için).
    const MAP_SLOTS = items.buildMapSlots(room.mapId);
    let mapOff = 106;
    for (const m of MAP_SLOTS) {
        p.writeUInt16LE(m.index,             mapOff + 0);    // u16 mapId
        p.writeUInt16LE(m.ruleIndex,         mapOff + 2);    // u16 ruleIndex
        p.writeUInt16LE(m.settingIndex,      mapOff + 4);    // u16 settingIndex
        p.writeUInt32LE(m.clanSetting,       mapOff + 6);    // u32 clan setting
        p.writeUInt8  (m.isFixWeapon,        mapOff + 10);   // IsFixWeapon
        p.writeUInt8  (m.priorityWeaponMode, mapOff + 11);   // PriorityWeaponMode
        p.writeUInt8  (m.isRoleChange,       mapOff + 12);   // IsRoleChange
        mapOff += 13;
    }

    // ----- Alt struct (sub_10072530 parser, payload[29]'dan başlar) -----
    //   alt[0]    = u8 flag             (this[0])
    //   alt[1..2] = u16 mapID/channelId (this+16) ← UI muhtemelen buradan map okuyor
    //   alt[3..]  = UTF-8 string nick   (this+8 wstring) — host nick
    p.writeUInt8  (1,                     29);
    p.writeUInt16LE((room.mapId || 10015) & 0xFFFF, 30);
    const hostName = (() => {
        for (const [, pl] of room.players) {
            const c = clients.get(pl.socket);
            if (c) return c.username || 'Host';
        }
        return 'Host';
    })();
    p.write       (hostName.slice(0, 24), 32, 24, 'utf8');

    p.writeUInt8  (room.friendlyFire ? 1 : 0, 185);
    p.writeUInt8  (room.autoBalance  ? 1 : 0, 186);

    p.writeUInt32LE(room.mapId || 10015, 187);    // 2. mapID alanı (sub_10072640 a2+203 → this+16 dword)
    p.writeUInt32LE(room.id,             191);    // roomId (sub_10072640 a2+207 → this+17 dword)

    return p;
}

// SN_Room_UserList payload.
// Reverse zinciri:
//   Dispatcher sub_101394F0 → parser sub_100720C0 → entry parser sub_10071F30 →
//   player ctor sub_100711B0 → render sub_1013DD80 (squad A/B Scaleform call'ları)
//
// Üst paket layout:
//   [0]      u8     header byte (parser okumuyor, 0)
//   [1]      u8     user count
//   [2..]    N × 49 byte (0x31) entry
//
// Entry layout (49 byte) ve client player struct (124 byte) eşleşmesi
// — sub_10071F30 ASM'sinden kesin reverse:
//
//   pkt offset  →  player offset  →  render etkisi
//   [0..1]   u16  → player[0x00]  → userId (host check + 'is me' karşılaştırma)
//   [2..5]   u32  → player[0x04]  → clanId (sub_10047470(0x17, val) clan icon lookup)
//   [6..9]   u32  → player[0x3C]  → render KULLANMIYOR (level/rank DEĞİL)
//   [10..11] u16  → player[0x08]  → team — A/B vector dağılımı için KRİTİK
//   [12..15] u32  → sub_1006F9F0 → player[0x0C] (1→1, 2→2, 3→3, 6→4, 8→5, 9→6, 0→0;
//                                  diğer = ctor default 7 → render "missing")
//   [16..19] u32  → player[0x10]  → render kullanmıyor (slot? — etkisi yok şimdilik)
//   [20..23] u32  → player[0x40]  → sub_10070740'a flag arg (display nick variant)
//   [24..48] str  → player[0x44]  → nick UTF-8 → UTF-16'ya çevrilir, render bu nick'i
//                                   sub_10070740 ile işleyip player[0x60]'a yazıp
//                                   ilk satır cell'ine basar
//
// Render player[0x34] (level icon /1000 switch) ve player[0x38] (rank icon /1000 switch)
// okuyor ama parser bunları YAZMIYOR — başka bir paketten gelmesi lazım (muhtemelen
// SN_UserColorNickInfo veya per-user record). Şimdilik 0 → switch default '.' icon.
function buildRoomUserListPayload(room) {
    const ENTRY_SIZE = 49;
    const p = Buffer.alloc(2 + room.players.size * ENTRY_SIZE);
    p.fill(0);

    p[0] = 0;
    p[1] = room.players.size;

    let off = 2;
    for (const [userId, pl] of room.players) {
        const c = clients.get(pl.socket);
        if (!c) { off += ENTRY_SIZE; continue; }

        p.writeUInt16LE(userId & 0xFFFF,                  off + 0);     // userId
        p.writeUInt32LE(userId,                           off + 2);     // clanId/fullId (icon arg)
        p.writeUInt32LE(0,                                off + 6);     // render kullanmıyor
        p.writeUInt16LE(pl.team,                          off + 10);    // team (1=A, 2=B, 0=spec)
        p.writeUInt32LE(1,                                off + 12);    // class index → mapped 1
        p.writeUInt32LE(pl.slot,                          off + 16);    // render kullanmıyor
        p.writeUInt32LE(userId === room.hostUserId ? 1 : 0, off + 20);  // nick variant flag
        p.write((c.username || '').slice(0, 24), off + 24, 24, 'utf8'); // nick UTF-8

        off += ENTRY_SIZE;
    }

    return p;
}

// SA_Room_Create — Hermit dispatcher zinciri:
//   1) IsPacketerrorMessage (sub_100D74A0) ÖNCE çağrılır:
//      payload[0..1] u16 errcode + payload[2..5] u32 reason okunur.
//      Reason != 0 → "MSG_ERROR_<reason>" popup tetiklenir.
//   2) Parser (sub_101392F0): payload[0..1] u8 pair (sub_1006FAC0)
//   Bu YÜZDEN min payload = 6 BYTE: tam errcode+reason = 0.
//   2 byte göndermek payload[2..5]'i uninitialized okutup random "reason" → popup.
async function send_SA_Room_Create(socket, ctx, room) {
    const p = Buffer.alloc(6);
    p.writeUInt16LE(0, 0);   // errcode = 0 (parser de payload[0..1] okur)
    p.writeUInt32LE(0, 2);   // reason  = 0 (IsPacketerrorMessage trigger eden field)
    await sendPacket(socket, ctx, PKT.SA_Room_Create, p);
}

async function send_SN_Room_Info(socket, ctx, room) {
    await sendPacket(socket, ctx, PKT.SN_Room_Info, buildRoomInfoPayload(room));
}

async function send_SN_Room_UserList(socket, ctx, room) {
    await sendPacket(socket, ctx, PKT.SN_Room_UserList, buildRoomUserListPayload(room));
}

// SN_Play_BaseRoomInfo — 27 byte PAYLOAD (raw packet 43 byte: 16 header + 27 payload).
// Reverse: sub_10070240 (BaseRoomInfo parser, GameClient.dll).
// Dispatcher sub_10138BA0 → sub_10070240(substate+0x120, RAW_PACKET_PTR).
// Parser raw byte stream'in [+0x10..+0x2A] arasını okuyor — header (16 byte) sonrası
// payload[0..26]'ya denk gelir. UserList parser de aynı pattern: count = raw[17] = payload[1].
//
// Payload offsets (raw - 16) → parser substate write → render etkisi:
//   [0..3]   u32  roomId          → substate[+0x00]                  oda kimliği
//   [4..5]   u16  team1 id        → substate[+0x04]; LOW→state[+0x30] team match A
//   [6..7]   u16  team2 id        → substate[+0x06]; LOW→state[+0x31] team match B
//   [8..9]   u16  team3 id        → substate[+0x08]; LOW→state[+0x32] team match spec
//   [10..11] u16  ?               → substate[+0x0A]
//   [12..13] u16  ?               → substate[+0x0C]
//   [14]     u8   ?               → substate[+0x0E]
//   [15..16] u16  ?               → substate[+0x10]
//   [17..18] u16  ?               → substate[+0x12]
//   [19..20] u16  ?               → substate[+0x14]
//   [21]     u8   ?               → substate[+0x16]
//   [22..23] u16  ?               → substate[+0x18]
//   [24..25] u16  ?               → substate[+0x1A]
//   [26]     u8   bool            → substate[+0x1C] bool
//
// KRİTİK: team1/2/3 LOW byte'ları sub_100720C0 (UserList parser) tarafından
// player.team ile karşılaştırılır:
//   - team1 LOW == player.team → vector A'ya insert (squad A satırı)
//   - team2 LOW == player.team → vector B'ye insert (squad B satırı)
//   - team3 LOW == player.team → ekstra insert YOK ama hata da yok (spectator)
//   - hiçbiri eşleşmezse: MessageBoxA("Missing nTeamIndex error!") + silent skip
// Server: team1=1, team2=2, team3=0; player.team ∈ {1,2} ile uyumlu.
function buildBaseRoomInfoPayload(room) {
    const p = Buffer.alloc(27);
    p.fill(0);

    p.writeUInt32LE(room.id,                 0);   // roomId
    p.writeUInt16LE(1,                       4);   // team1 id (red)  → A squad
    p.writeUInt16LE(2,                       6);   // team2 id (blue) → B squad
    p.writeUInt16LE(0,                       8);   // team3 id (spec)
    p.writeUInt16LE(room.mapId & 0xFFFF,    10);   // mapId tahmini
    p.writeUInt16LE(room.gameMode,          12);   // gameMode tahmini
    p.writeUInt8  (room.gameType || 1,      14);   // gameType tahmini
    p.writeUInt16LE(0,                      15);   // ?
    // payload[17] u8 = MISSION LOOKUP KEY (sub_100CB380 'char a2' alıyor — u8!).
    // sub_100CB380 RB-tree lookup → [GameModeMgr+612] → sub_100476A0 switch:
    //   0=TDM  1=Bomb(?)  3=Rescue  4=Carry  5=Conquest  7=FlexibleCapture
    //   8=TDMS  9=Captin  10=RescueKey  11=Single
    // Lookup table CSettingTableLoader ile populate ediliyor — table'da yoksa -1.
    // Client'ın seçtiği gerçek mode'u gönder (zorla 0 yerine):
    //   - TDM=0, Bomb=1, Rescue=3, Carry=4, Conquest=5, FlexibleCapture=7,
    //     TDMS=8, Captin=9, RescueKey=10, Single=11
    // Yanlış key gönderince client GetController null görüp uyarı pop-up basıyor.
    // room.gameMode CQ_Create'ten parse edilen değer (1 default).
    p.writeUInt8  (room.gameMode || 1,      17);   // mission lookup key
    p.writeUInt8  (0,                       18);
    // payload[19..20] u16 = round time MINUTES (60×X = saniye)
    // payload[37]    u8  = ? (sub_100CBEC0 → GameModeMgr+60)
    // payload[38..39] u16 = ? (GameModeMgr+28)
    // payload[40..41] u16 = ? (GameModeMgr+76)
    p.writeUInt16LE(Math.max(1, Math.floor((room.timeLimit || 180) / 60)), 19);
    p.writeUInt8  (room.roundCount || 10,   21);
    p.writeUInt16LE(0,                      22);
    p.writeUInt16LE(room.players.size,      24);
    p.writeUInt8  (room.autoBalance ? 1 : 0, 26);

    return p;
}

async function send_SN_Play_BaseRoomInfo(socket, ctx, room) {
    await sendPacket(socket, ctx, PKT.SN_Play_BaseRoomInfo, buildBaseRoomInfoPayload(room));
}

// SN_Play_BaseUserList — özgün format, 270 byte entry.
// Reverse: sub_100CB7B0 (BaseUserList parser).
//
// Layout:
//   [0]      u8     header byte
//   [1]      u8     user count
//   [2..3]   u16    İLK entry'nin userId
//   [4..5]   u16    İLK entry'nin team
//   [6..]    N × 270 byte entry
//
// Entry layout (270 byte):
//   [0..N]     UTF-8 null-terminated nick (eşleşme için kullanılıyor)
//   [4..269]   diğer veriler (avatar/equipment/clan?)
//   [266..267] u16  BİR SONRAKİ entry'nin userId
//   [268..269] u16  BİR SONRAKİ entry'nin team
//
// Parser nick ile room.players'tan match arar; bulduğu player struct'ın userId+team
// alanlarını günceller (yeni squad pozisyonu için).
// SN_Play_BaseUserList — 270-byte entry pattern (GameServer.dll HandleMatchup case 1
// ASM doğrulaması: packet[18..19]=userId, packet[20..21]=team, packet[292..294]=stats).
// Eski emülatörün "sub-packet" teorisi YANLIŞ — IDA'da 0x6C immediate sadece 2 yerde,
// sub-packet pattern olsa onlarca olurdu.
//
// Layout:
//   [0]      u8   header byte
//   [1]      u8   user count
//   [2..3]   u16  ilk entry'nin userId (parser packet[18..19]'dan okuyor)
//   [4..5]   u16  ilk entry'nin team   (parser packet[20..21]'den okuyor)
//   [6..]    N×270 byte entry (nick + diğer alanlar)
//   sondaki 32 byte padding: parser packet[292..294] OOB read önle
function buildBaseUserListPayload(room) {
    const ENTRY = 270;
    const HEADER = 6;
    const TAIL_PADDING = 32;
    const players = [...room.players.values()];
    const n = players.length;

    const p = Buffer.alloc(HEADER + n * ENTRY + TAIL_PADDING);
    p.fill(0);

    p[0] = 0;
    p[1] = n;

    if (n >= 1) {
        const first = players[0];
        const c0 = clients.get(first.socket);
        if (c0) {
            p.writeUInt16LE(c0.userId & 0xFFFF, 2);
            p.writeUInt16LE(first.team,         4);
        }
    }

    let off = HEADER;
    for (let i = 0; i < n; i++) {
        const pl = players[i];
        const c = clients.get(pl.socket);
        if (!c) { off += ENTRY; continue; }

        p.write((c.username || '').slice(0, 32), off, 32, 'utf8');

        if (i + 1 < n) {
            const next = players[i + 1];
            const nextC = clients.get(next.socket);
            if (nextC) {
                p.writeUInt16LE(nextC.userId & 0xFFFF, off + ENTRY - 4);
                p.writeUInt16LE(next.team,             off + ENTRY - 2);
            }
        }

        off += ENTRY;
    }

    // packet[292..294] stats (HandleMatchup case 1 reverse)
    if (n >= 1) {
        p.writeUInt8(1, 276);
        p.writeUInt8(1, 277);
        p.writeUInt8(1, 278);
    }

    return p;
}

// SN_Play_BattleInfo (0x222114) — KRİTİK paket: MissionController + squad
// finalizer. Bunu göndermeden squad list-render dispatcher (sub_1013DD80) doğru
// player+96/98/100 flag'lerini bulamıyor → squad satırları boş kalıyor.
//
// Reverse — sub_100CA860 (full packet ptr a1, 16-byte header dahil; payload[N] = a1[16+N]):
//   a1[17]      u8        entry count                      → payload[1]
//   a1[49..72]  6 × u32   game rule params                 → payload[33..56]
//                         sub_1040FAF0(arg1..arg6) — sub_103FCB20 globals'a yazılır
//   a1[73..74]  u16       İLK entry'nin userId             → payload[57..58]
//                         (parser İLK iter'da *(v4-3) = a1+73 = payload[57] okur)
//   a1[79..]    N × 20    ENTRY — payload[63..] (v4 = a1+79, v4 += 10 her iter):
//     entry[0..1]   u16  stat1 → player+96
//     entry[2..3]   u16  stat2 → player+98
//     entry[4..5]   u16  stat3 → player+100
//     entry[6..13]  -    8 byte ?
//     entry[14..15] u16  NEXT entry'nin userId (sonraki iter'da *(v4-3) buradan okur)
//     entry[16..19] -    4 byte ?
//
//   Loop sonrası: v8 = *(globalState+56)+48 = GameMode obj
//                 v9 = vtable[5](v8) = mission type (1/3/5/7/9/10)
//                 GameRule[+612] = v9 → CMissionMgr OnEnterWorld doğru CMission'ı yaratır
//                 (1=DeathMatch, 3=Bomb, 5=Capture, 7=Rescue, 9=Captin)
//
// player+96/98/100 globalState+48/49/50 (team1Id/team2Id/team3Id) ile aynı offset →
// "bu kullanıcı için team1Id-match / team2Id-match / team3Id-match" flag'leri.
// Squad render bu değerleri okuyup A/B/spec slot'una yerleştirir.
function buildBattleInfoPayload(room) {
    const p = Buffer.alloc(512);
    p.fill(0);

    const players = [...room.players.values()];
    const n = Math.min(players.length, 16);
    p[1] = n;

    // 6 game rule params @ payload[33..56] — sub_1040FAF0
    p.writeUInt32LE(room.roundCount || 10,   33);
    p.writeUInt32LE(room.timeLimit  || 180,  37);
    p.writeUInt32LE(room.scoreLimit || 100,  41);
    p.writeUInt32LE(room.missionType || 1,   45);
    p.writeUInt32LE(room.ruleIndex  || 3006, 49);
    p.writeUInt32LE(room.mapId      || 10006, 53);

    // İLK entry'nin userId @ payload[57..58]
    if (n >= 1) {
        const firstC = clients.get(players[0].socket);
        if (firstC) p.writeUInt16LE(firstC.userId & 0xFFFF, 57);
    }

    // Entries başlangıcı payload[63] (NOT 57!). Her entry 20 byte.
    let off = 63;
    for (let i = 0; i < n; i++) {
        const pl = players[i];
        const c = clients.get(pl.socket);
        if (!c) { off += 20; continue; }

        // stat1/2/3 → player+96/98/100 (team1Id/team2Id/team3Id matching).
        // BaseRoomInfo'da team1=1, team2=2, team3=0 kullandığımız için bu sıraya uyduruyoruz.
        p.writeUInt16LE(1, off + 0);   // stat1 = team1Id
        p.writeUInt16LE(2, off + 2);   // stat2 = team2Id
        p.writeUInt16LE(0, off + 4);   // stat3 = team3Id

        // SONRAKI entry'nin userId — bu entry'nin son kuyruğunda (offset 14..15)
        if (i + 1 < n) {
            const nextC = clients.get(players[i + 1].socket);
            if (nextC) p.writeUInt16LE(nextC.userId & 0xFFFF, off + 14);
        }

        off += 20;
        if (off + 20 > p.length) break;
    }

    return p;
}

async function send_SN_Play_BattleInfo(socket, ctx, room) {
    await sendPacket(socket, ctx, PKT.SN_Play_BattleInfo, buildBattleInfoPayload(room));
}

// SN_Result_GameFinalResult (0x222221) — TEK PAKET / TÜM OYUNCULAR (8'e kadar).
//
// 🔬 PROBE TEST DOĞRULADI (Blue=4444 ✓ payload[10], Red=5555 ✓ payload[22]):
//   Parser sub_10158A60 → qmemcpy(entry, packet, 811) — packet HAM (16 byte header dahil)
//   entry[N] = packet[N] = payload[N - 16]
//
// 811-byte entry struct format (sub_10159840'tan reverse):
//   entry[0..49]   = TEAM TOPLAM SCORE bölümü (Blue/Red wKill/wGoal/wScore)
//   entry[50]      = SUB-ENTRY COUNT (0..8)         ← ZORUNLU, bu olmadan loop dönmez
//   entry[51..]    = N × 95 byte PLAYER SUB-ENTRY   ← her oyuncu için 1
//   50 + 1 + 8 × 95 = 811 ✓
//
// Payload (16-byte header shift):
//   payload[10..11]  = entry[26..27] = wScore Blue (TEAM toplam)
//   payload[22..23]  = entry[38..39] = wScore Red  (TEAM toplam)
//   payload[34]      = entry[50]     = sub-entry count
//   payload[35 + i*95 + ...]         = sub-entry i (95 byte/player)
//
// 95-byte SUB-ENTRY layout (sub_10159840 v75 erişimleri):
//   sub[0..1]    u16  userId  ← sub_10070AA0(*v75) lookup, başarısızsa entry SKIP
//   sub[2]       u8   stat byte (kill)
//   sub[3]       u8   stat byte (death)
//   sub[5]       u8   stat byte (point)
//   sub[16..19]  u32  skill1 dword (wide-string convert input)
//   sub[28..29]  u16  data
//   sub[30..33]  u32  skill2 dword
//   sub[38..53]  8×u16  per-round score pairs (mapping karmaşık, şimdilik sıfır)
function buildGameFinalResultPayload(room, opts = {}) {
    const p = Buffer.alloc(811);
    p.fill(0);

    const players = [...room.players.values()];
    const n = Math.min(players.length, 8);

    // ──────── TEAM TOPLAM SCORE (entry[0..49] = payload[-16..33], header'la çakışan kısım atılır) ────────
    // Sadece okunabilen alanlar (entry >= 16 → payload >= 0):
    p.writeUInt16LE(opts.blueScore ?? 0, 10);   // entry[26..27] = wScore Blue
    p.writeUInt16LE(opts.redScore  ?? 0, 22);   // entry[38..39] = wScore Red

    // ──────── SUB-ENTRY COUNT (entry[50] = payload[34]) ────────
    p[34] = n;

    // ──────── PER-PLAYER SUB-ENTRY (95 byte each) ────────
    for (let i = 0; i < n; i++) {
        const pl = players[i];
        const c = clients.get(pl.socket);
        if (!c) continue;
        const subOff = 35 + i * 95;   // entry[51 + i*95] = payload[35 + i*95]
        const stat = opts.playerStats?.[c.userId] || {
            kill:  pl.team === 1 ? 5 : 3,
            death: pl.team === 1 ? 2 : 4,
            point: pl.team === 1 ? 10 : 6,
        };

        p.writeUInt16LE(c.userId & 0xFFFF,    subOff + 0);    // sub[0..1] userId (lookup zorunlu)
        p.writeUInt8  (stat.kill   ?? 0,      subOff + 2);    // sub[2] kill
        p.writeUInt8  (stat.death  ?? 0,      subOff + 3);    // sub[3] death
        p.writeUInt8  (stat.point  ?? 0,      subOff + 5);    // sub[5] point
        p.writeUInt32LE(stat.skill1 ?? 1000,  subOff + 16);   // sub[16..19] skill1
        p.writeUInt16LE(stat.data28 ?? 0,     subOff + 28);   // sub[28..29] data
        p.writeUInt32LE(stat.skill2 ?? 1000,  subOff + 30);   // sub[30..33] skill2
    }

    return p;
}

async function send_SN_Result_GameFinalResult(socket, ctx, room, opts) {
    await sendPacket(socket, ctx, PKT.SN_Result_GameFinalResult,
        buildGameFinalResultPayload(room, opts));
}

async function send_SN_Play_BaseUserList(socket, ctx, room) {
    await sendPacket(socket, ctx, PKT.SN_Play_BaseUserList, buildBaseUserListPayload(room));
}

// SN_Hosting_HostConnect — client'ı dedicated server'a yönlendiren paket.
// Bunu alınca client lobby UI'sını kapatıp loading ekranına geçer ve verilen IP:port'a
// bağlanmaya çalışır.
//
// Reverse (eski emülatör kodundan):
//   Buffer 512 byte (Buffer.alloc(512))
//   payload[0]    u16  port (örn. 27888 = 0x6CF0)  ← 0x10 - xOffset(16) = 0
//   payload[3..]  utf8 server IP (null-terminated, "127.0.0.1" gibi)  ← 0x13 - 16 = 3
function send_SN_Hosting_HostConnect(socket, ctx, ip, port) {
    const p = Buffer.alloc(512);
    p.fill(0);
    p.writeUInt16LE(port, 0);
    p.write(ip, 3, Math.min(ip.length, 15), 'utf8');
    return sendPacket(socket, ctx, PKT.SN_Hosting_HostConnect, p);
}

async function send_SN_User_State(socket, ctx, userId, state) {
    // state: 1 = lobby, 2 = room, 3 = playing
    const p = Buffer.alloc(16);
    p.fill(0);
    p.writeUInt32LE(userId, 0);
    p.writeUInt8  (state,  4);
    p.writeUInt32LE(Date.now() >>> 0, 8);
    await sendPacket(socket, ctx, PKT.SN_User_State, p);
}

async function send_SN_Room_UpdateInfoToChannelUser(channelId, room, exceptSocket = null) {
    await broadcastChannel(channelId, PKT.SN_Room_UpdateInfoToChannel, buildRoomInfoPayload(room), exceptSocket);
}

// --------------------------------------------------------------------------
// ROOM LIFECYCLE
// --------------------------------------------------------------------------

// CQ_Create payload formatı (kullanıcının gerçek paket dump'larından çıkarıldı):
//   [0]      u8     roomType
//   [1..2]   u16 LE mapID
//   [3]      u8     room name max length (sabit 0x27 = 39)
//   [18..]   str    roomName (UTF-8 null-term, max ~16 byte)
//   [son]    u8 + str  password flag (0x01) + password string
// CQ_Room_Create — TAM REVERSE (sub_10131F10 SendRoomCreate + sub_10070C20 serializer)
//
// Packet boyutu: 0x73 = 115 byte (16 header + 99 payload).
// LOG'DAN DOĞRULANMIŞ FIELD ANLAMLARI:
//   - Map.csv'de 10015 = Paradise (5-digit) — payload[2..3] = u16 → MAP ID
//   - payload[6] = 1   → lastRoundNumber (round sayısı)
//   - payload[7..8] = 100 → score limit
//   - payload[14] = 6  → gameMode/category (small enum)
//   - payload[15] = 1  → roomType
//
// Serializer (sub_10070C20) WRITE OFFSET'leri:
//   payload[ 0]    u8   flag (this[88], default 0)
//   payload[ 1]    u8   field A (this[73] = a23)
//   payload[ 2..3] u16  MAP ID  (this+64 = a19)                     ← Map.csv index
//   payload[ 4..5] u16  ?? (this[78] = a26 — boundary/timer)
//   payload[ 6]    u8   lastRoundNumber (this[74] = a24, printf'le doğrulandı)
//   payload[ 7..8] u16  scoreLimit (this[76] = a25)
//   payload[ 9..10] u16 LOW16(a20) — userId/seed
//   payload[11..12] u16 toggle: 512 if this[83]=1 else 0            ← clan/private flag
//   payload[13]    u8   field E (this[92] = a34)
//   payload[14]    u8   gameMode/category (this[72] = a22)
//   payload[15]    u8   ROOM TYPE (a2: 1=normal, 2=clan, 3=quick…)
//   payload[16..17] u16 name wstring length metadata (this+2 = a3)
//   payload[18..74] str ROOM NAME (utf-8, null-terminated, max 57)
//   payload[76]    u8   field H (this[32] = a11)
//   payload[77..86] str PASSWORD (ascii, null-terminated, max 10)
//   payload[88]    u8   field I (this[84] = a30 — friendly fire?)
//   payload[89]    u8   field J (this[93] = a28 — auto balance?)
//   payload[90]    u8   field K (this[100] = a36)
//   payload[91..94] u32 field L (this+96 = a35)
//   payload[95..98] u32 0 (padding)
function parseCreateRoomRequest(payload) {
    if (payload.length < 99) {
        console.warn(`[ROOM-PARSE] short payload: ${payload.length} byte`);
    }

    const roomType        = payload.length > 15 ? payload[15] : 1;
    const mapId           = payload.length > 3  ? payload.readUInt16LE(2) : 10015;
    const lastRoundNumber = payload.length > 6  ? payload[6]  : 1;
    const scoreLimit      = payload.length > 8  ? payload.readUInt16LE(7) : 100;
    const altTimer        = payload.length > 5  ? payload.readUInt16LE(4) : 180;
    const gameMode        = payload.length > 14 ? payload[14] : 1;
    const flagToggle      = payload.length > 12 ? payload.readUInt16LE(11) : 0;
    const isClanRoom      = (flagToggle === 512);
    const friendlyFire    = payload.length > 88 ? payload[88] !== 0 : false;
    const autoBalance     = payload.length > 89 ? payload[89] !== 0 : true;

    // Room name @ payload[18..74] (max 57 byte utf-8, null-terminated)
    let name = 'Oda';
    if (payload.length > 18) {
        let end = 18;
        while (end < Math.min(payload.length, 18 + 57) && payload[end] !== 0) end++;
        const cand = payload.slice(18, end).toString('utf8').trim();
        if (cand) name = cand;
    }

    // Password @ payload[77..86] (max 10 byte ASCII, null-terminated)
    let password = null;
    if (payload.length > 77) {
        let end = 77;
        while (end < Math.min(payload.length, 77 + 10) && payload[end] !== 0) end++;
        const cand = payload.slice(77, end).toString('ascii').trim();
        if (cand && /^[\x20-\x7E]+$/.test(cand)) password = cand;
    }

    const maxPlayers = 16;   // serializer'da yok (UI seçer)
    const timeLimit  = 180;  // CQ payload'da explicit yok; default

    console.log(`[ROOM-PARSE] type=${roomType} mapId=${mapId} mode=${gameMode} round=${lastRoundNumber} score=${scoreLimit} altTimer=${altTimer} clan=${isClanRoom} ff=${friendlyFire} ab=${autoBalance} name="${name}" pw="${password||''}"`);

    return {
        type           : roomType,
        name,
        password,
        mapId,                  // u16 Map.csv index (örn 10015 = Paradise)
        gameMode,               // u8 game mode/category
        gameType       : 1,
        roundCount     : lastRoundNumber || 1,
        timeLimit,
        scoreLimit,
        maxPlayers,
        isClanRoom,
        boundary       : 0,
        friendlyFire,
        autoBalance,
    };
}

async function createRoom(socket, ctx, req) {
    // Default güvenli map (Vehicle/Mission entity içermeyen DeathMatch).
    // Map.csv'den ruleIndex okuyup CMissionMgr type'ını da hesaplıyoruz
    // (CMissionMgr::GetController() popup'ı önlemek için OnEnterWorld'ün
    //  doğru mission controller'ı yaratması lazım).
    const safeMapId = req.mapId || items.getDefaultSafeMapId();
    const mapMeta   = items.getMap(safeMapId);
    const ruleIdx   = mapMeta ? mapMeta.ruleIndex : 3006;
    const missionType = items.getMissionTypeForRule(ruleIdx);

    const room = {
        id           : nextRoomId++,
        name         : req.name,
        type         : req.type,
        password     : req.password,
        maxPlayers   : req.maxPlayers,
        mapId        : safeMapId,
        ruleIndex    : ruleIdx,                                 // Map.csv RuleIndex (3002/3006/3007/...)
        missionType  : missionType,                             // CMissionMgr type (1/3/5/7/9/10)
        gameMode     : req.gameMode    || 1,
        gameType     : req.gameType    || 1,
        roundCount   : req.roundCount  || 10,
        timeLimit    : req.timeLimit   || 180,
        scoreLimit   : req.scoreLimit  || 100,
        boundary     : req.boundary    || 0,
        isClanRoom   : req.isClanRoom  || false,
        friendlyFire : req.friendlyFire ?? false,
        autoBalance  : req.autoBalance  ?? true,
        hostUserId   : ctx.userId,
        channelId    : ctx.channelId || CONFIG.DEFAULT_CHANNEL,
        players      : new Map(),
        status       : 'waiting',
        createdAt    : Date.now(),
    };
    room.players.set(ctx.userId, { socket, slot: 0, team: 1, ready: false });
    rooms.set(room.id, room);
    console.log(`[LOBBY] room created mapId=${safeMapId} (${mapMeta?mapMeta.name+' '+mapMeta.mode:'?'}) rule=${ruleIdx} → missionType=${missionType}`);

    ctx.roomId = room.id;
    ctx.team   = 1;
    ctx.slot   = 0;

    console.log(`[LOBBY] room created #${room.id} "${room.name}" host=${ctx.userId} type=${room.type} max=${room.maxPlayers}`);

    // Host'a oda yaratıldı bilgisi ver
    await send_SA_Room_Create        (socket, ctx, room);
    await send_SN_Room_Info          (socket, ctx, room);
    // BaseRoomInfo MUTLAKA UserList'ten ÖNCE gelmeli — sub_10070240 globalleri
    // (team1Id/team2Id/team3Id @ +48/+49/+50) burada SET ediliyor; sub_100720C0
    // (UserList parser) entry.team'i bu globallerle karşılaştırıyor. Aksi halde
    // her entry "team match yok" olarak işaretlenip squad'a eklenmiyor.
    await send_SN_Play_BaseRoomInfo  (socket, ctx, room);
    await send_SN_Room_UserList      (socket, ctx, room);
    await send_SN_User_State         (socket, ctx, ctx.userId, 2);
    await send_SN_Play_BaseUserList  (socket, ctx, room);
    // SN_Play_BattleInfo — KRİTİK: GameRule[+612] = missionType set ediyor.
    // Bu paket olmadan CMissionMgr OnEnterWorld default CMission yaratıyor →
    // level entity'leri için GetController() popup'ı atıyor.
    await send_SN_Play_BattleInfo    (socket, ctx, room);
    // ÖNEMLİ: SN_HostConnect createRoom'da gönderilmez! Client onu görür görmez
    // StartGameAsClient() çağırıp maça girmeye çalışır. HostConnect sadece "Start"
    // basıldığında (dedicated bağlıyken) SN_BattleStart ile birlikte gönderilir.

    // Channel'daki diğer oyunculara odanın listede gözükmesi için update broadcast
    await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room, socket);

    return room;
}

async function enterRoom(socket, ctx, roomId) {
    const room = rooms.get(roomId);
    if (!room) return;
    if (room.players.size >= room.maxPlayers) return;
    if (room.status !== 'waiting') return;

    // Slot ve takım bul
    const usedSlots = new Set([...room.players.values()].map(p => p.slot));
    let slot = 0; while (usedSlots.has(slot)) slot++;
    const team = (slot % 2) + 1;

    room.players.set(ctx.userId, { socket, slot, team, ready: false });
    ctx.roomId = room.id;
    ctx.team   = team;
    ctx.slot   = slot;

    console.log(`[LOBBY] user ${ctx.userId} joined room #${room.id}, slot ${slot}, team ${team}`);

    // Yeni gelene tam bilgi
    const okPayload = Buffer.alloc(16);
    writeOkHeader(okPayload);
    okPayload.writeUInt32LE(room.id, 6);
    await sendPacket(socket, ctx, PKT.SA_Room_EnterUser, okPayload);
    await send_SN_Room_Info        (socket, ctx, room);
    // BaseRoomInfo ÖNCE — team1Id/team2Id/team3Id globallerini set eder.
    await send_SN_Play_BaseRoomInfo(socket, ctx, room);
    await send_SN_Room_UserList    (socket, ctx, room);
    await send_SN_User_State       (socket, ctx, ctx.userId, 2);
    await send_SN_Play_BaseUserList(socket, ctx, room);
    // SN_Play_BattleInfo — GameRule[+612]'yi set ederek CMissionMgr'ın doğru
    // mission controller'ı yaratmasını sağlar (GetController popup'ı önler).
    await send_SN_Play_BattleInfo  (socket, ctx, room);

    // Diğer oyunculara güncel kullanıcı listesi
    await broadcastRoom(room.id, PKT.SN_Room_UserList, buildRoomUserListPayload(room), socket);
    await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room);
}

async function leaveRoom(socket, ctx) {
    const room = rooms.get(ctx.roomId);
    if (!room) return;

    const leavingId = ctx.userId;
    const wasHost   = (room.hostUserId === leavingId);

    room.players.delete(leavingId);
    ctx.roomId = null;

    console.log(`[LOBBY] user ${leavingId} left room #${room.id} (host=${wasHost})`);

    // Çıkana ack
    const ack = Buffer.alloc(8);
    writeOkHeader(ack);
    await sendPacket(socket, ctx, PKT.SA_Room_LeaveUser, ack).catch(() => {});
    await send_SN_User_State(socket, ctx, leavingId, 1).catch(() => {});

    if (room.players.size === 0) {
        // Oda boşaldı, kapat
        rooms.delete(room.id);
        await send_SN_Room_UpdateInfoToChannelUser(room.channelId, { ...room, players: new Map(), status: 'closed' });
        return;
    }

    // Host gittiyse ilk kalan host olur
    if (wasHost) {
        const [newHostId] = room.players.keys();
        room.hostUserId = newHostId;
        const leaderPayload = Buffer.alloc(8);
        leaderPayload.writeUInt32LE(newHostId, 0);
        await broadcastRoom(room.id, PKT.SN_Room_ChangeLeader, leaderPayload);
    }

    // Odaya çıkışı bildir
    const leavePayload = Buffer.alloc(8);
    leavePayload.writeUInt32LE(leavingId, 0);
    await broadcastRoom(room.id, PKT.SN_Room_LeaveUser, leavePayload);
    await broadcastRoom(room.id, PKT.SN_Room_UserList, buildRoomUserListPayload(room));
    await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room);
}

// --------------------------------------------------------------------------
// HEARTBEAT
// --------------------------------------------------------------------------

async function send_SA_HeartbeatAck(socket, ctx) {
    const p = Buffer.alloc(8);
    p.writeUInt32BE(1734441331, 0);
    p.writeUInt32BE(0, 4);
    await sendPacket(socket, ctx, PKT.SA_HeartbeatAck, p);
}

async function send_SA_KeepAliveAck(socket, ctx) {
    const p = Buffer.alloc(4);
    p.writeUInt32BE(0, 0);
    await sendPacket(socket, ctx, PKT.SA_KeepAliveAck, p);
}

// --------------------------------------------------------------------------
// HANGAR / EQUIPMENT — formatlar kullanıcının çalışan kodundan port
// --------------------------------------------------------------------------

// SA_Open: hangar/dükkan/envanter açma cevabı.
// Format (CDispatch_TCP_NEquipment_SA_Open::Dispatch sub_10031770'tan reverse):
//   off 0..1   : error code (u16)   — 0 = success
//   off 2..5   : error reason (u32)
//   off 6..9   : cash / GP (u32)        → state+128
//   off 10..13 : premium cash (u32)     → state+132
//   off 14..17 : mode (u32) ← KRİTİK    → 0=hiçbir scene; switch ile UI seçer
//                  1 = sceneType 4, flag 0   (Inventory ekranı)
//                  2 = sceneType 4, flag 1
//                  3 = sceneType 13          (Shop ekranı tahmini)
//                  4 = sceneType 5
//                  5 = sceneType 4, flag 3
async function send_SA_Hangar_Open(socket, ctx, mode = 1) {
    const inv = storage.getOrCreateInventory(ctx.username || 'Player');
    const money = inv.money || { gold: 0, cash: 0 };
    const p = Buffer.alloc(18);
    p.writeUInt16LE(0,           0);     // err code = success
    p.writeUInt32LE(0,           2);     // err reason
    p.writeUInt32LE(money.gold,  6);     // gold (cash/GP)
    p.writeUInt32LE(money.cash, 10);     // cash (premium)
    p.writeUInt32LE(mode,       14);     // mode → UI scene selector
    await sendPacket(socket, ctx, PKT.SA_Hangar_Open, p);
}

// SA_Hangar_Close — sub_10031890: errcode + reason yeterli (6 byte)
async function send_SA_Hangar_Close(socket, ctx) {
    await sendPacket(socket, ctx, PKT.SA_Hangar_Close, helpers.buildErrorAck());
}

// SA_Hangar_ChangePart — sub_10030F80: sadece errcode + reason (6 byte)
// Parser hangi item'ı equip ettiğini state[+104]'ten okur (CQ'da set edildi)
async function send_SA_Hangar_ChangePart(socket, ctx) {
    await sendPacket(socket, ctx, PKT.SA_Hangar_ChangePart, helpers.buildErrorAck());
}

// SA_Hangar_Unequip — sub_10149070: errcode + slotType (1=primary, 2=secondary) + itemId + sub
async function send_SA_Hangar_Unequip(socket, ctx, slotType = 1, itemId = 0, sub = 0) {
    const p = Buffer.alloc(18);
    p.writeUInt16LE(0,        0);   // errcode
    p.writeUInt32LE(0,        2);   // reason
    p.writeUInt32LE(slotType, 6);   // 1 = primary, 2 = secondary
    p.writeUInt32LE(itemId,  10);   // unequipped item ID
    p.writeUInt32LE(sub,     14);   // sub-slot index
    await sendPacket(socket, ctx, PKT.SA_Hangar_Unequip, p);
}

// SA_Hangar_ActiveItem — sub_1003D880: errcode + reason + itemId(2×u32) + activeFlag
// activeFlag != 0 → item state[+5544] = activeFlag (item activated/expiry set)
// activeFlag == 0 → item removed from active
async function send_SA_Hangar_ActiveItem(socket, ctx, itemId = 0, activeFlag = 1) {
    const p = Buffer.alloc(18);
    p.writeUInt16LE(0,          0);    // errcode
    p.writeUInt32LE(0,          2);    // reason
    p.writeUInt32LE(itemId,     6);    // itemId LOW (sub_100087D0(low, high))
    p.writeUInt32LE(0,         10);    // itemId HIGH (= 0 for normal items)
    p.writeUInt32LE(activeFlag,14);    // active flag / expiry
    await sendPacket(socket, ctx, PKT.SA_Hangar_ActiveItem, p);
}

// SA_Hangar_DeleteItem — sub_10149170: errcode + reason + itemId
async function send_SA_Hangar_DeleteItem(socket, ctx, itemId = 0) {
    const p = Buffer.alloc(10);
    p.writeUInt16LE(0,      0);
    p.writeUInt32LE(0,      2);
    p.writeUInt32LE(itemId, 6);   // deleted item ID (UI shows "destroyed" message)
    await sendPacket(socket, ctx, PKT.SA_Hangar_DeleteItem, p);
}

// SA_Hangar_UseItem — sub_100420B0: errcode + reason + itemId(2×u32) + activeFlag
async function send_SA_Hangar_UseItem(socket, ctx, itemId = 0, activeFlag = 0) {
    const p = Buffer.alloc(20);
    p.writeUInt16LE(0,          0);
    p.writeUInt32LE(0,          2);
    p.writeUInt32LE(itemId,     6);    // itemId LOW
    p.writeUInt32LE(0,         10);    // itemId HIGH
    p.writeUInt16LE(0,         14);    // padding
    p.writeUInt32LE(activeFlag,16);    // 0 = consumed (removed), nonzero = updated
    await sendPacket(socket, ctx, PKT.SA_Hangar_UseItem, p);
}

// SN_PackageItem — sub_10148B80: "item envantere eklendi" push paketi
// CashBuy/Buy/UseItem sonrası gerçek envanter eklemesi BU paket ile bildirilir.
// SA_CashBuy sadece "ConfirmDialog" açıyor (Flash event); item gerçekten
// inventory'e eklenmiyor — SN_PackageItem geldiğinde client `sub_101F59D0`
// ile template lookup yapıp `sub_101F83D0` ile ekliyor.
//
// Format SN_ItemList ile aynı:
//   payload[0]: header (?)
//   payload[1]: u8 count
//   payload[2..]: count × 27-byte entry
//     entry[0..3]: itemId LOW
//     entry[4..7]: itemId HIGH (= 0)
//     entry[8]:    active flag
//     entry[9..12]: state[+3996]
//     entry[13..16]: state[+4000]
//     entry[17..20]: state[+4004]
//     entry[21..22]: state[+4008] u16
//     entry[23..26]: state[+5544]
async function send_SN_PackageItem(socket, ctx, items) {
    const arr = Array.isArray(items) ? items : [items];
    const ENTRY = 27;
    const p = Buffer.alloc(2 + arr.length * ENTRY);
    p[0] = 0;
    p[1] = arr.length;
    // Permanent item için creation/expiry'i çok uzak gelecek timestamp olarak set
    // ediyoruz. sub_101F83D0 (inventory.add) state[+4000] alanını expiry validation
    // için kullanıyor olabilir; 0 → "süresi dolmuş" sayılıp reddedilir → "아이템 생성 실패!"
    const PERMANENT_EXPIRY = 0x7FFFFFFF;     // u32 max signed = 2038-01-19 (effectively permanent)
    const NOW = Math.floor(Date.now() / 1000);
    let off = 2;
    for (const it of arr) {
        const created = it.created || NOW;
        const expiry  = (it.expiry && it.expiry > 0) ? it.expiry : PERMANENT_EXPIRY;
        p.writeUInt32LE(it.id || 0,        off + 0);    // itemId LOW
        p.writeUInt32LE(0,                 off + 4);    // itemId HIGH
        p.writeUInt8   (it.active ? 1 : 0, off + 8);    // active flag → state[+5740]
        p.writeUInt32LE(created,           off + 9);    // creation time → state[+3996]
        p.writeUInt32LE(expiry,            off + 13);   // expiry → state[+4000] (validation!)
        p.writeUInt32LE(0,                 off + 17);   // state[+4004]
        p.writeUInt16LE(0,                 off + 21);   // state[+4008]
        p.writeUInt32LE(expiry,            off + 23);   // state[+5544] (also expiry-related)
        off += ENTRY;
    }
    await sendPacket(socket, ctx, PKT.SN_PackageItem, p);
}

// SA_Hangar_Buy — sub_10148DF0: gold satın alma cevabı
// errcode + reason + newGold + newCash + (16 byte misc) + slotCount(u8) + N×u32 newItemIds
async function send_SA_Hangar_Buy(socket, ctx, itemId = 0, errcode = 0) {
    const inv = ctx.username ? storage.getOrCreateInventory(ctx.username) : null;
    const money = inv ? inv.money : { gold: 0, cash: 0 };
    const p = Buffer.alloc(23);
    p.writeUInt16LE(errcode,    0);
    p.writeUInt32LE(0,          2);
    p.writeUInt32LE(money.gold, 6);
    p.writeUInt32LE(money.cash,10);
    // payload[14..17] = misc (parser skip)
    p.writeUInt8   (1,         18);   // slot count = 1
    p.writeUInt32LE(itemId,    19);   // newly added item ID
    await sendPacket(socket, ctx, PKT.SA_Hangar_Buy, p);
}

// SA_Hangar_CashBuy — sub_10149290: cash satın alma cevabı
// errcode + reason + newGold + newCash + (16 byte misc) + itemId(u32)
async function send_SA_Hangar_CashBuy(socket, ctx, itemId = 0, errcode = 0) {
    const inv = ctx.username ? storage.getOrCreateInventory(ctx.username) : null;
    const money = inv ? inv.money : { gold: 0, cash: 0 };
    const p = Buffer.alloc(22);
    p.writeUInt16LE(errcode,    0);
    p.writeUInt32LE(0,          2);
    p.writeUInt32LE(money.gold, 6);
    p.writeUInt32LE(money.cash,10);
    // payload[14..17] = misc (parser skip)
    p.writeUInt32LE(itemId,    18);
    await sendPacket(socket, ctx, PKT.SA_Hangar_CashBuy, p);
}

// --------------------------------------------------------------------------
// DEDICATED SERVER HANDSHAKE
//
// TheRawServer.exe lobby'e bağlanınca CQ_TheRawServer_Connect (0x410101)
// gönderir; payload içinde encryption key + dedicated bilgisi var.
// Lobby bunu kaydeder, ardından bu socket'i client değil dedicated olarak
// işler.  Tam payload yapısı henüz reverse edilmedi — şimdilik ham payload
// loglanır + key ham olarak çıkarılmaya çalışılır.
// --------------------------------------------------------------------------

// CQ_TheRawServer_Connect (0x410101) payload format — GameServer.dll sub_100D16C0
// builder reverse'inden teyit. Toplam 43 byte (header 16 + payload 27):
//
//   payload[0..3]    DWORD  flag = 1   (anlamı henüz net değil — "init complete"?)
//   payload[4..5]    WORD   port       (CHermitNetworkMgr this+72; lobby connect port'u)
//   payload[6]       BYTE   sub-flag   (CHermitNetworkMgr this+74 düşük byte)
//   payload[7..21]   CHAR   IP string  (15 byte max, dedi'nin DediPublicIP veya
//                                       Game.ini HermitDediConnectIP değeri)
//   payload[22]      BYTE   0          (null terminator)
//   payload[23..26]  DWORD  serverId   (CHermitNetworkMgr this+120)
function handleDedicatedConnect(socket, ctx, decrypted) {
    const payload = decrypted.slice(16);
    console.log(`[DEDI] handshake from ${socket.remoteAddress}, payload (${payload.length}): ${payload.toString('hex')}`);

    if (payload.length < 27) {
        console.warn(`[DEDI] payload too short (${payload.length} < 27) — handshake invalid`);
        return;
    }

    const flag      = payload.readUInt32LE(0);
    const port      = payload.readUInt16LE(4);
    const subFlag   = payload[6];
    const ipString  = readCString(payload, 7, 15);
    const serverId  = payload.length >= 27 ? payload.readUInt32LE(23) : 0;

    // Loopback override: dedi TCP üzerinden 127.0.0.1'den bağlandıysa, client'a da
    // 127.0.0.1 vermeliyiz; çünkü dedi handshake'te kendi LAN IP'sini bildiriyor
    // (örn. 192.168.1.149) ve client 127.0.0.1'den UDP'yi LAN IP'ye yollarsa
    // loopback yönlendirmesi başarısız olur → spawn paketleri (engine MID 103
    // PLAYER_STATE_CHANGE) ulaşmaz → client InWorld'da PlayerState=5 (Spectator)
    // loop'unda kalır.
    const remoteIp = (socket.remoteAddress || '').replace(/^::ffff:/, '');
    const isLocal  = remoteIp === '127.0.0.1' || remoteIp === '::1';
    const effectiveIp = isLocal ? '127.0.0.1' : (ipString || '127.0.0.1');

    const dedi = {
        id      : ctx.id,
        roomId  : null,
        ip      : effectiveIp,
        ipReported : ipString,           // dedi'nin handshake'te bildirdiği IP (debug)
        port    : port || 27888,        // dedi'nin UDP gameplay port'u (TheRaw.exe -port)
        flag, subFlag, serverId,
        rawHex  : payload.toString('hex'),
    };
    dedicateds.set(socket, dedi);
    ctx.isDedicated = true;
    console.log(`[DEDI] registered ip=${dedi.ip}${dedi.ipReported && dedi.ipReported !== dedi.ip ? ` (reported=${dedi.ipReported}, loopback override)` : ''} port=${dedi.port} flag=${flag} subFlag=${subFlag} serverId=0x${serverId.toString(16)}`);

    // Eğer ilgili odanın oyuncuları varsa, onlara doğru host bilgisini gönder
    if (dedi.roomId) {
        const room = rooms.get(dedi.roomId);
        if (room) {
            broadcastRoom(room.id, PKT.SN_Hosting_HostConnect, (() => {
                const p = Buffer.alloc(512);
                p.fill(0);
                p.writeUInt16LE(dedi.port, 0);
                p.write(dedi.ip, 3, Math.min(dedi.ip.length, 15), 'utf8');
                return p;
            })()).catch(() => {});
        }
    }
}

// --------------------------------------------------------------------------
// MAIN DISPATCHER
// --------------------------------------------------------------------------

async function processPacket(socket, dec, ctx) {
    const opcode = dec.readUInt32LE(12);
    const size   = dec.readUInt16LE(6);
    const reqSeq = dec.readUInt16LE(4);

    // Heartbeat/keepalive için req_seq mirror; diğer paketlerde kendi sayacımız.
    if (opcode === PKT.CQ_Heartbeat || opcode === PKT.CQ_KeepAlive || opcode === PKT.CQ_KeepAliveAck
        || opcode === PKT.CQ_KeepAlive2 || opcode === PKT.CQ_KeepAlive2Status) {
        ctx.sequence = reqSeq;
    }

    console.log(`[LOBBY←${ctx.id.slice(0,6)}] recv 0x${opcode.toString(16)} ${PKT_ALL.NAME(opcode)} (size ${size}, reqSeq ${reqSeq})`);

    try {
        switch (opcode) {

            // ---- SİSTEM ----
            case PKT.CQ_HackShield: break;
            case PKT.CQ_Heartbeat:    await send_SA_HeartbeatAck(socket, ctx); break;
            case PKT.CQ_KeepAlive:    await send_SA_KeepAliveAck(socket, ctx); break;
            case PKT.CQ_KeepAliveAck: break;

            // CQ_KeepAlive2 (0x20084) — sessiz kabul (önceden ack ekleyince dedi
            // BAN'a düşüyordu, eski davranışa dönüldü).
            case PKT.CQ_KeepAlive2: break;
            case PKT.CQ_KeepAlive2Status: break;

            // ---- LOBBY GİRİŞ ----
            // Client sunucu seçim sonrası lobby'ye gelir, "server select okeyleme" olarak
            // CQ_Join (1114404) gönderir. Biz sadece SA_Join ile cevap veririz; envanter,
            // user info gibi şeyler zaten auth tarafında gönderildi.
            case PKT.CQ_Join: {
                // Lobby'ye gelen CQ_Join AUTH'a gelen CQ_JoyGameLogin'den FARKLI:
                // sadece 8-byte handshake (auth'taki 33-byte username payload yok).
                // Squad render zinciri:
                //   sub_1013DD80 → sub_10070E80(substate) → sub_10070AD0(container, MY_NICK)
                //   MY_NICK = state[+8].nick (login'de set edildi, AUTH'tan gelen değer)
                // Eğer UserList entry'sinde gönderdiğimiz nick MY_NICK ile eşleşmezse render
                // erken exit ediyor → squad list boş.
                //
                // SHARED STATE: auth_server login bittikten sonra _session/users.json'a
                // ipAddress → { username, userId } yazıyor; lobby buradan IP üzerinden
                // matchliyor (geliştirme/lokal için yeterli, prod'da daha sıkı).
                const payload = dec.length > 16 ? dec.slice(16) : Buffer.alloc(0);
                console.log(`[LOBBY] CQ_Join payload (${payload.length} byte): ${payload.toString('hex')}`);

                const ip = (socket.remoteAddress || '').replace(/^::ffff:/, '');
                const sess = lookupAuthSession(ip);
                if (sess) {
                    ctx.username = sess.username;
                    ctx.userId   = sess.userId;
                    console.log(`[LOBBY] CQ_Join matched auth session: username="${ctx.username}" userId=${ctx.userId} ip=${ip}`);
                } else {
                    ctx.username = ctx.username || `User${(Math.abs(hashStr(ctx.id)) % 10000)}`;
                    ctx.userId   = ctx.userId || ((Math.abs(hashStr(ctx.id)) % 1_000_000) + 1);
                    console.warn(`[LOBBY] CQ_Join NO auth session for ip=${ip} — fallback username="${ctx.username}" (squad render BOZUK olur, state[+8].nick eşleşmez)`);
                }
                // Auth disconnect/reconnect sonrası client'ın channel list'i temizleniyor;
                // SA_Join'a ek olarak GroupList + ChannelList yeniden gönderilmeli, yoksa
                // ChannelList scene açılır → liste boş → bounce back ServerList'e.
                await sendLobbyEntryBundle(socket, ctx);
                break;
            }

            // ---- KANAL ----
            // Client kanal seçim isteği. Akış:
            //   1) SA_EnterUser_Channel → "kanal açıldı"
            //   2) SN_UserList_Channel → kanaldaki tüm user'ları gönder
            //   3) Diğer kanal user'larına BROADCAST: yeni user için güncel UserList
            case PKT.CQ_EnterUser_Channel: {
                const channelId = CONFIG.DEFAULT_CHANNEL;
                const ch = channels.get(channelId);
                if (ch) {
                    ch.sockets.add(socket);
                    ctx.channelId = ch.id;
                }
                console.log(`[LOBBY] ${ctx.username || ctx.id.slice(0,6)} CQ_Channel_Select → ch=${channelId} (size=${ch ? ch.sockets.size : 0})`);
                await send_SA_EnterUser_Channel(socket, ctx);
                await send_SN_UserList_Channel(socket, ctx);
                // Diğer user'lara güncellenmiş list yolla
                if (ch) {
                    for (const otherSock of ch.sockets) {
                        if (otherSock === socket) continue;
                        const otherCtx = clients.get(otherSock);
                        if (otherCtx) {
                            try { await send_SN_UserList_Channel(otherSock, otherCtx); } catch (_) {}
                        }
                    }
                }
                break;
            }

            case PKT.CQ_LeaveUser_Channel: {
                const channelId = ctx.channelId;
                if (channelId) {
                    const ch = channels.get(channelId);
                    if (ch) ch.sockets.delete(socket);
                    ctx.channelId = null;
                }
                const ack = Buffer.alloc(8); writeOkHeader(ack);
                await sendPacket(socket, ctx, PKT.SA_LeaveUser_Channel, ack);
                // Kalan user'lara güncellenmiş list yolla (ayrılan kişi düşsün)
                if (channelId) {
                    const ch = channels.get(channelId);
                    if (ch) {
                        for (const otherSock of ch.sockets) {
                            const otherCtx = clients.get(otherSock);
                            if (otherCtx) {
                                try { await send_SN_UserList_Channel(otherSock, otherCtx); } catch (_) {}
                            }
                        }
                    }
                }
                break;
            }

            // ---- HANGAR / EQUIPMENT ----
            // Hangar Open dükkan + envanter ekranını açar. SA_Open sonrası ItemList ve
            // SlotInfo göndererek envanter dolu gözüksün.
            case PKT.CQ_Hangar_Open:
                await send_SA_Hangar_Open(socket, ctx);
                await send_SN_ItemList   (socket, ctx);
                await send_SN_SlotInfo   (socket, ctx);
                break;

            case PKT.CQ_Hangar_Close:       await send_SA_Hangar_Close      (socket, ctx); break;

            // CQ_Hangar_ChangePart — slot değiştir.
            // Payload: u32 itemId @ payload[0..3]
            // Slot mapping items.js'den (TotalItem.csv ItemType+MediumGroup):
            //   weapon medium 1=primary, 2=secondary, 3=melee, 4=grenade
            //   character medium 1=character, 2=costumeHead, 3=costumeBody, 4=costumeBack
            // Tablo'da yoksa fallback: item ID prefix'i (eski 7-digit + cash shop 9-digit).
            case PKT.CQ_Hangar_ChangePart: {
                const itemId = dec.length >= 20 ? dec.readUInt32LE(16) : 0;
                if (itemId && ctx.username) {
                    const inv = storage.getOrCreateInventory(ctx.username);
                    const it  = inv.items.find(x => x.id === itemId);
                    if (it) {
                        let slotKey = items.getSlotKey(itemId);
                        if (!slotKey) {
                            // Fallback: ID prefix → slot
                            const pref = parseInt(String(itemId).slice(0, 2), 10);
                            if      (pref === 11) slotKey = 'primary';
                            else if (pref === 12) slotKey = 'secondary';
                            else if (pref === 13) slotKey = 'melee';
                            else if (pref === 14) slotKey = 'grenade';
                            else if (pref === 21) slotKey = 'character';
                        }
                        if (slotKey) {
                            inv.slots[slotKey] = itemId;
                            storage.saveInventory(ctx.username, inv);
                            const meta = items.getItem(itemId);
                            console.log(`[LOBBY] ${ctx.username} ChangePart slot=${slotKey} itemId=${itemId} (${meta?meta.name:'?'})`);
                        } else {
                            console.log(`[LOBBY] ${ctx.username} ChangePart itemId=${itemId} → slot mapping bulunamadı`);
                        }
                    } else {
                        console.log(`[LOBBY] ${ctx.username} ChangePart itemId=${itemId} NOT FOUND in inventory`);
                    }
                }
                await send_SA_Hangar_ChangePart(socket, ctx);
                await send_SN_SlotInfo(socket, ctx);
                break;
            }

            // CQ_Hangar_Unequip — slot'tan eşya çıkar.
            // Payload: parser sub_10149070 reverse: u32 slotType + u32 itemId.
            //   slotType 1 = primary, 2 = secondary
            // Pratik: itemId verilmişse o item'ı tüm slotlardan kaldır.
            case PKT.CQ_Hangar_Unequip: {
                const slotType = dec.length >= 20 ? dec.readUInt32LE(16) : 0;
                const itemId   = dec.length >= 24 ? dec.readUInt32LE(20) : 0;
                if (ctx.username) {
                    const inv = storage.getOrCreateInventory(ctx.username);
                    const targetId = itemId || slotType;   // itemId yoksa slotType'ı dene
                    let cleared = false;
                    for (const k of Object.keys(inv.slots)) {
                        if (inv.slots[k] === targetId) {
                            inv.slots[k] = 0;
                            cleared = true;
                        }
                    }
                    if (cleared) storage.saveInventory(ctx.username, inv);
                    console.log(`[LOBBY] ${ctx.username} Unequip slotType=${slotType} itemId=${itemId} cleared=${cleared}`);
                }
                await send_SA_Hangar_Unequip(socket, ctx);
                await send_SN_SlotInfo(socket, ctx);
                break;
            }

            // CQ_Hangar_ActiveItem — eşyayı aktif et (silah aktivasyonu vb.)
            case PKT.CQ_Hangar_ActiveItem: {
                const itemId = dec.length >= 20 ? dec.readUInt32LE(16) : 0;
                if (itemId && ctx.username) {
                    const inv = storage.getOrCreateInventory(ctx.username);
                    const it  = inv.items.find(x => x.id === itemId);
                    if (it) {
                        it.active = 1;
                        storage.saveInventory(ctx.username, inv);
                        console.log(`[LOBBY] ${ctx.username} ActiveItem itemId=${itemId}`);
                    }
                }
                await send_SA_Hangar_ActiveItem(socket, ctx, itemId);
                await send_SN_ItemList(socket, ctx);
                break;
            }

            // CQ_Hangar_DeleteItem — eşyayı envanterden sil
            case PKT.CQ_Hangar_DeleteItem: {
                const itemId = dec.length >= 20 ? dec.readUInt32LE(16) : 0;
                if (itemId && ctx.username) {
                    const inv = storage.getOrCreateInventory(ctx.username);
                    const idx = inv.items.findIndex(x => x.id === itemId);
                    if (idx >= 0) {
                        inv.items.splice(idx, 1);
                        // Aynı zamanda equipped slot'tan da çıkar
                        for (const k of Object.keys(inv.slots)) {
                            if (inv.slots[k] === itemId) inv.slots[k] = 0;
                        }
                        storage.saveInventory(ctx.username, inv);
                        console.log(`[LOBBY] ${ctx.username} DeleteItem itemId=${itemId}`);
                    }
                }
                await send_SA_Hangar_DeleteItem(socket, ctx, itemId);
                await send_SN_ItemList(socket, ctx);
                break;
            }

            // CQ_Hangar_UseItem — tüketilebilir eşya kullan (qty -= 1)
            case PKT.CQ_Hangar_UseItem: {
                const itemId = dec.length >= 20 ? dec.readUInt32LE(16) : 0;
                if (itemId && ctx.username) {
                    const inv = storage.getOrCreateInventory(ctx.username);
                    const it  = inv.items.find(x => x.id === itemId);
                    if (it) {
                        it.qty = Math.max(0, (it.qty || 1) - 1);
                        if (it.qty === 0) {
                            const idx = inv.items.indexOf(it);
                            inv.items.splice(idx, 1);
                        }
                        storage.saveInventory(ctx.username, inv);
                        console.log(`[LOBBY] ${ctx.username} UseItem itemId=${itemId} (qty→${it.qty})`);
                    }
                }
                await send_SA_Hangar_UseItem(socket, ctx, itemId);
                await send_SN_ItemList(socket, ctx);
                break;
            }

            // CQ_Hangar_CashBuy / CQ_Hangar_Buy — satın alma (cash veya gold)
            // Payload: u32 itemId @ payload[0..3] (CashBuy log'undan doğrulandı)
            //
            // Gerçek fiyat: Shop.csv'den (items.getShopEntry).
            // Gerçek süre:  TotalItem.csv Limite (dakika cinsinden, items.getItemDurationSec).
            //   - IsPeriod=0 ya da Limite=0    → permanent (expiry=0)
            //   - Limite=99999999              → permanent
            //   - Diğer                        → o kadar dakika
            // Mevcut item üzerine alınırsa süre uzatılır (existing.expiry + duration).
            //
            // Sıra:
            //   1) SA_Hangar_CashBuy/Buy → UI ConfirmDialog (yeni gold/cash gösterir)
            //   2) SN_PackageItem → client envantere ekler (template lookup + add)
            //   3) SN_ItemList → tam envanter sync (yedek)
            case PKT.CQ_Hangar_CashBuy:
            case PKT.CQ_Hangar_Buy: {
                const isCash = (opcode === PKT.CQ_Hangar_CashBuy);
                const itemId = dec.length >= 20 ? dec.readUInt32LE(16) : 0;

                if (!itemId || !ctx.username) {
                    if (isCash) await send_SA_Hangar_CashBuy(socket, ctx, 0, 1);
                    else        await send_SA_Hangar_Buy   (socket, ctx, 0, 1);
                    break;
                }

                // Shop.csv lookup: gerçek fiyat + cash/gold tipi
                const shopEntry = items.getShopEntry(itemId);
                const itemMeta  = items.getItem(itemId);
                let price = shopEntry ? shopEntry.price : (isCash ? 100 : 1000);   // tablo yoksa default
                // Shop.IsCash mismatch: kullanıcı CashBuy gönderdiyse cash'ten düş
                // (Shop.csv genelde tek satıra sahip, IsCash flag ile opcode eşleşmesi
                //  client tarafından doğrulanır — biz opcode'a göre çekiyoruz)
                const ok = isCash
                    ? storage.chargeCash(ctx.username, price)
                    : storage.chargeGold(ctx.username, price);
                if (!ok) {
                    console.log(`[LOBBY] ${ctx.username} ${isCash?'CashBuy':'Buy'} REJECT itemId=${itemId} price=${price} (yetersiz bakiye)`);
                    if (isCash) await send_SA_Hangar_CashBuy(socket, ctx, itemId, 1);
                    else        await send_SA_Hangar_Buy   (socket, ctx, itemId, 1);
                    break;
                }

                // Süre: TotalItem.csv Limite (dakika) → saniye. 0 = permanent.
                const durationSec = items.getItemDurationSec(itemId);
                const inv = storage.getOrCreateInventory(ctx.username);
                const NOW = Math.floor(Date.now() / 1000);
                const it  = inv.items.find(x => x.id === itemId);

                if (it) {
                    // Süre uzatma: permanent itemde no-op; period itemde mevcut süre + duration
                    if (durationSec > 0) {
                        const base = (it.expiry && it.expiry > NOW) ? it.expiry : NOW;
                        it.expiry = base + durationSec;
                    } else {
                        it.expiry = 0;   // permanent
                    }
                    it.qty = (it.qty || 0) + 1;
                } else {
                    inv.items.push({
                        id      : itemId,
                        qty     : 1,
                        active  : 0,
                        created : NOW,
                        expiry  : durationSec > 0 ? NOW + durationSec : 0,
                    });
                }
                storage.saveInventory(ctx.username, inv);
                const newIt = inv.items.find(x => x.id === itemId);
                const dur = durationSec ? `${Math.floor(durationSec/86400)}gün` : 'permanent';
                console.log(`[LOBBY] ${ctx.username} ${isCash?'CashBuy':'Buy'} itemId=${itemId} (${itemMeta?itemMeta.name:'?'}) price=${price} dur=${dur} → gold=${inv.money.gold} cash=${inv.money.cash}`);

                if (isCash) await send_SA_Hangar_CashBuy(socket, ctx, itemId);
                else        await send_SA_Hangar_Buy   (socket, ctx, itemId);
                await send_SN_PackageItem(socket, ctx, newIt);
                await send_SN_ItemList   (socket, ctx);
                break;
            }

            // ---- CLAN ----
            // CQ_Guild_Factory_Create (0x360221) — klan kur.
            // Payload yapısı (parser tam reverse edilmedi; gözlem):
            //   [0..63]  klan adı  (UTF-8 null-terminated, max ~32 char)
            //   [64..127] kuruluş açıklaması
            //   [128..]  flags / mark id
            // Klan adını payload[0..]'tan UTF-8 null-terminated okuyoruz.
            // Başarı: SA_Guild_Factory_Create (errcode=0) + SN_UserInfo refresh (klan adı dolu).
            case PKT_ALL.CQ_Guild_Factory_Create: {
                if (!ctx.username) {
                    await sendPacket(socket, ctx, PKT_ALL.SA_Guild_Factory_Create, helpers.buildErrorAck(1, 0));
                    break;
                }
                const clanName = readCString(dec, 16, 32).trim();
                if (!clanName) {
                    await sendPacket(socket, ctx, PKT_ALL.SA_Guild_Factory_Create, helpers.buildErrorAck(1, 0));
                    break;
                }
                const clanId = (Date.now() & 0x7FFFFFFF);
                storage.setClan(ctx.username, {
                    id       : clanId,
                    name     : clanName,
                    mark     : 0,
                    rank     : 2,           // master (kurucu)
                    joinedAt : Math.floor(Date.now() / 1000),
                });
                console.log(`[LOBBY] ${ctx.username} CLAN_CREATE name="${clanName}" id=${clanId}`);
                await sendPacket(socket, ctx, PKT_ALL.SA_Guild_Factory_Create, helpers.buildErrorAck(0, 0));
                await send_SN_UserInfo(socket, ctx);
                break;
            }

            // ---- ROOM ----
            case PKT.CQ_Room_Create: {
                const req = parseCreateRoomRequest(dec.slice(16));
                await createRoom(socket, ctx, req);
                break;
            }

            case PKT.CQ_Room_EnterUser: {
                // Payload genelde roomId içerir. Bulamazsak boş ilk odaya katıl.
                let roomId = dec.length >= 20 ? dec.readUInt32LE(16) : 0;
                if (!rooms.has(roomId)) {
                    for (const [id, r] of rooms) if (r.status === 'waiting' && r.players.size < r.maxPlayers) { roomId = id; break; }
                }
                if (rooms.has(roomId)) await enterRoom(socket, ctx, roomId);
                break;
            }

            case PKT.CQ_Room_LeaveUser:
                await leaveRoom(socket, ctx);
                break;

            // Oda chat — NN_ prefix = iki yönlü (client→server→client'lar).
            // Client'ın gönderdiği payload'u oda içindeki HERKESE (gönderen DAHİL)
            // aynı opcode ile broadcast'liyoruz — gönderenin kendi mesajı UI'da
            // görünsün diye 'except' parametresi yok.
            // Payload formatı (47+ byte, tam reverse edilmedi):
            //   [0]      u8   header byte
            //   [1..2]   u16  ?  (channel/type tahmini)
            //   [3..]    str  message UTF-8 null-terminated
            //   [...]    binary blob (Scaleform formatting/color tags tahmini)
            // Şimdilik AYNI BUFFER aynen yansıtılıyor; sender id gerekirse ileride eklenir.
            // NN_NotBattleAll (0x220505) — "battle olmayan all chat"
            //   - Oyuncu odada ise: oda içine broadcast (eski davranış)
            //   - Oyuncu sadece kanaldaysa: kanaldaki herkese broadcast
            // Sender'ın kendisi de mesajı görmeli (echo) — Flash UI bunu beklediği için
            // exceptSocket=null geçiyoruz (broadcastRoom/Channel default null = herkese).
            case PKT.NN_Chat_NotBattleAll: {
                const payload = dec.length > 16 ? dec.slice(16) : Buffer.alloc(0);
                if (ctx.roomId) {
                    console.log(`[LOBBY] room-chat from ${ctx.username} in room ${ctx.roomId} (${payload.length} byte)`);
                    await broadcastRoom(ctx.roomId, PKT.NN_Chat_NotBattleAll, payload);
                } else if (ctx.channelId) {
                    console.log(`[LOBBY] channel-chat from ${ctx.username} in ch ${ctx.channelId} (${payload.length} byte)`);
                    await broadcastChannel(ctx.channelId, PKT.NN_Chat_NotBattleAll, payload);
                } else {
                    console.log(`[LOBBY] chat ignored: ${ctx.username} not in room/channel`);
                }
                break;
            }

            // NN_Chat_BattleAll (0x220509) / NN_Chat_BattleTeam (0x220507) —
            // match içinde chat. Client gönderir, lobby odadaki herkese (BattleAll)
            // veya sadece aynı takıma (BattleTeam) forward eder. Payload format
            // (canlı dump 2026-04-30): virtualIndex u16 + chat metni + state floats.
            // Lobby decode etmez, ham payload relay eder.
            case PKT.NN_Chat_BattleAll:
            case PKT.NN_Chat_BattleTeam: {
                const payload = dec.length > 16 ? dec.slice(16) : Buffer.alloc(0);
                const isTeam = (opcode === PKT.NN_Chat_BattleTeam);
                if (ctx.roomId) {
                    console.log(`[LOBBY] ${isTeam ? 'team' : 'battle'}-chat from ${ctx.username} in room ${ctx.roomId} (${payload.length} byte)`);
                    // TODO: BattleTeam için sadece aynı takım filtrelenmeli (şimdilik herkese gidiyor).
                    await broadcastRoom(ctx.roomId, opcode, payload);
                } else {
                    console.log(`[LOBBY] ${isTeam ? 'team' : 'battle'}-chat ignored: ${ctx.username} not in room`);
                }
                break;
            }

            // ============================================================
            // CN_Chat_DevCommand (0x220522) — admin/scmd console komutu.
            // Reverse: GameClient.dll sub_10236700 ("CmdTcpFn <command>").
            //   Format: 272 byte total = 16 hdr + 256 payload (string buffer)
            //   payload[0..255] = ascii komut, null-terminated
            //
            // LithTech Scmd komutları (GameServer.dll IDS_SCMD_HELP_*'tan):
            //   help, login <pwd>, logout, listclients, listmissions,
            //   nextmission, nextround, setmission <name>,
            //   bootname <name>, bootid <id>,
            //   listgameoptions, showgameoption <name>, setgameoption <k> <v>
            //
            // Login akışı: client console'da 'CmdTcpFn login <password>'.
            // Server (Server/GM_Auth.csv) IP+ID+Password lookup; eşleşirse
            // ctx.isAdmin=true → diğer komutlar açılır.
            // ============================================================
            // (Eski PKT.CQ_Chat_DevCommand referansı dispatcher'a uydu: CN prefix, cevap yok)
            case PKT.CN_Chat_DevCommand: {
                if (dec.length < 17) break;
                let end = 16;
                while (end < dec.length && dec[end] !== 0) end++;
                let cmd = dec.slice(16, end).toString('utf8').trim();
                if (!cmd) break;

                // Client console'da slash-prefix var: "/login 123" veya "/CmdTcpFn login 123".
                // Önce "/" varsa kırp, sonra "CmdTcpFn" varsa onu da çıkar.
                if (cmd.startsWith('/')) cmd = cmd.slice(1).trim();
                if (/^CmdTcpFn\s+/i.test(cmd)) cmd = cmd.replace(/^CmdTcpFn\s+/i, '').trim();
                if (!cmd) break;

                const args = cmd.split(/\s+/);
                const op = (args[0] || '').toLowerCase();
                const remoteIp = (socket.remoteAddress || '').replace(/^::ffff:/, '');
                console.log(`[LOBBY] DevCommand from ${ctx.username}@${remoteIp}: "${cmd}"  (op=${op})`);

                const sendFail = async (msg) => {
                    console.log(`[LOBBY]   ↳ FAIL: ${msg}`);
                    const p = Buffer.alloc(64);
                    p.write(msg.slice(0, 63), 0, 63, 'utf8');
                    await sendPacket(socket, ctx, PKT.SN_Chat_DevCommandFail, p);
                };

                if (op === 'login') {
                    // 'login <pwd>' → ID = ctx.username
                    // 'login <id> <pwd>' → ID = arg[1]
                    let user, pwd;
                    if (args.length === 2)      { user = ctx.username; pwd = args[1]; }
                    else if (args.length >= 3)  { user = args[1];      pwd = args[2]; }
                    else { await sendFail('usage: login [<id>] <password>'); break; }

                    if (items.checkGmAuth(remoteIp, user, pwd)) {
                        ctx.isAdmin = true;
                        ctx.adminId = user;
                        console.log(`[LOBBY]   ↳ ADMIN LOGIN OK (${user}@${remoteIp})`);
                        // Lobby tarafı bilgilendirme yok — server tarafı "AdminLoggedIn" mesajını
                        // chat olarak echo edebilir; şimdilik sadece flag set.
                    } else {
                        await sendFail(`incorrect login: ${user}/${pwd}`);
                    }
                    break;
                }

                if (op === 'logout') {
                    if (ctx.isAdmin) {
                        console.log(`[LOBBY]   ↳ ADMIN LOGOUT (${ctx.adminId})`);
                        ctx.isAdmin = false;
                        ctx.adminId = null;
                    }
                    break;
                }

                // Aşağıdaki komutlar admin gerektirir
                if (!ctx.isAdmin) { await sendFail('not logged in (use: login <pwd>)'); break; }

                switch (op) {
                    case 'help':
                        console.log(`[LOBBY]   ↳ help: login, logout, setmap <id>, nextmap, listmaps, listclients`);
                        break;
                    case 'setmap': {
                        const id = parseInt(args[1], 10);
                        if (!id || !items.getMap(id)) { await sendFail(`unknown mapId: ${args[1]}`); break; }
                        process.env.S2_DEFAULT_MAP = String(id);
                        const m = items.getMap(id);
                        console.log(`[LOBBY]   ↳ default map → ${id} (${m.name} ${m.mode})`);
                        break;
                    }
                    case 'listclients': {
                        let i = 0;
                        for (const [s, c] of clients) console.log(`[LOBBY]   #${++i} ${c.username||'?'} (${(s.remoteAddress||'').replace(/^::ffff:/,'')})`);
                        break;
                    }
                    case 'listmaps': {
                        const all = items.loadMaps();
                        const limit = parseInt(args[1] || '20', 10);
                        let i = 0;
                        for (const [id, m] of all) {
                            if (i++ >= limit) break;
                            console.log(`[LOBBY]   ${id}  ${m.mode.padEnd(12)} ${m.name}`);
                        }
                        break;
                    }
                    default:
                        console.log(`[LOBBY]   ↳ unknown admin command: ${op}`);
                }
                break;
            }

            // ============================================================
            // ODA AYAR DEĞİŞİKLİKLERİ — sadece host yapabilir
            // CQ opcode'lar IDA builder reverse'iyle teyit:
            //   0x220211 ChangeBoundary (1 byte payload)
            //   0x220215 ChangeOption   (3 byte payload)
            //   0x220218 ChangeName     (58 byte payload)
            //   0x22021B ChangePassword (12 byte payload)
            //   0x220221 ChangeMapInfo  (14 byte payload)
            //
            // Pattern: SA_* ack (errcode+reason = 0) + SN_* broadcast (yeni değer).
            // SA cevap formatı IsPacketerrorMessage check'i için min 6 byte gerekli.
            // ============================================================

            // CQ_Room_ChangeMapInfo (0x220221) — sub_1013B7E0 SendChangeMapInfo reverse:
            //   payload[ 0]    = 0           (always)
            //   payload[ 1..2] = u16 MAP ID  (cache+64 = a18; örn 10018 = MoonNight)
            //   payload[ 3..4] = u16 a25     (round/time field)
            //   payload[ 5]    = u8  a23     (lastRoundNumber? cache[74])
            //   payload[ 6..7] = u16 a24     (cache+76)
            //   payload[ 8..9] = u16 LOW16(a19) = scoreLimit/groupId
            //   payload[10..11] = u16 0/512  (clan/private toggle)
            //   payload[12]    = u8 a30      (cache[92])
            //   payload[13]    = u8 a21      (cache[72] — endByte)
            case PKT.CQ_Room_ChangeMapInfo: {
                const room = rooms.get(ctx.roomId);
                if (!room || room.hostUserId !== ctx.userId) break;
                const rawPL = dec.slice(16);
                const newMapId = dec.length >= 19 ? dec.readUInt16LE(17) : room.mapId;
                const fldA     = dec.length >= 21 ? dec.readUInt16LE(19) : 0;
                const newScore = dec.length >= 26 ? dec.readUInt16LE(24) : room.scoreLimit;
                const clanTog  = dec.length >= 28 ? dec.readUInt16LE(26) : 0;
                room.mapId      = newMapId;
                room.scoreLimit = newScore;
                room.isClanRoom = (clanTog === 512);

                const meta = items.getMap(newMapId);
                console.log(`[LOBBY] room#${room.id} ChangeMapInfo mapId=${newMapId} (${meta?meta.name+' '+meta.mode:'?'}) score=${newScore} fldA=${fldA} clan=${room.isClanRoom}`);
                console.log(`[LOBBY]   raw payload (${rawPL.length}b): ${rawPL.toString('hex')}`);

                await sendPacket(socket, ctx, PKT.SA_Room_ChangeMapInfo, helpers.buildErrorAck());
                // SN_Room_Info SADECE diğer üyelere — host'un UI'sı kendi local state'iyle
                // zaten güncel; tekrar göndermek "ChangeRule.confirm" akışında 5 SN_Room_Info
                // arka arkaya gelmesine sebep oluyor ve client çakıyor (ECONNRESET).
                await broadcastRoom(room.id, PKT.SN_Room_Info, buildRoomInfoPayload(room), socket);
                await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room, socket);
                break;
            }

            // CQ_Room_ChangeName (0x220218) — sub_1013C520 reverse:
            //   sprintf(packet+16, "%s", roomName) → payload[0..57] = utf-8 isim, null-term, max 57 byte.
            //   Sadece TEK string var (eski isim falan değil).
            case PKT.CQ_Room_ChangeName: {
                const room = rooms.get(ctx.roomId);
                if (!room || room.hostUserId !== ctx.userId) break;
                const rawPL = dec.slice(16);
                let end = 16;
                while (end < Math.min(dec.length, 16 + 57) && dec[end] !== 0) end++;
                const newName = dec.slice(16, end).toString('utf8').trim();
                if (newName) {
                    const old = room.name;
                    room.name = newName;
                    console.log(`[LOBBY] room#${room.id} ChangeName "${old}" → "${newName}"`);
                } else {
                    console.log(`[LOBBY] room#${room.id} ChangeName ignored (empty)`);
                }
                console.log(`[LOBBY]   raw payload (${rawPL.length}b): ${rawPL.toString('hex')}`);

                await sendPacket(socket, ctx, PKT.SA_Room_ChangeName, helpers.buildErrorAck());
                // SN_Room_Info SADECE diğer üyelere — host'a gönderme (crash önleme).
                await broadcastRoom(room.id, PKT.SN_Room_Info, buildRoomInfoPayload(room), socket);
                await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room, socket);
                break;
            }

            // CQ_Room_ChangeOption (0x220215) — 3 byte payload:
            //   [0] u8 ??           (genelde 0)
            //   [1] u8 friendlyFire (0/1)
            //   [2] u8 autoBalance  (0/1)
            case PKT.CQ_Room_ChangeOption: {
                const room = rooms.get(ctx.roomId);
                if (!room || room.hostUserId !== ctx.userId) break;
                const rawPL = dec.slice(16);
                if (dec.length >= 19) {
                    room.friendlyFire = dec[17] !== 0;
                    room.autoBalance  = dec[18] !== 0;
                }
                console.log(`[LOBBY] room#${room.id} ChangeOption ff=${room.friendlyFire} ab=${room.autoBalance}`);
                console.log(`[LOBBY]   raw payload (${rawPL.length}b): ${rawPL.toString('hex')}`);

                await sendPacket(socket, ctx, PKT.SA_Room_ChangeOption, helpers.buildErrorAck());
                await broadcastRoom(room.id, PKT.SN_Room_Info, buildRoomInfoPayload(room), socket);
                break;
            }

            // CQ_Room_ChangeBoundary (0x220211) — 1 byte payload: u8 boundary (level limiti)
            case PKT.CQ_Room_ChangeBoundary: {
                const room = rooms.get(ctx.roomId);
                if (!room || room.hostUserId !== ctx.userId) break;
                const rawPL = dec.slice(16);
                if (dec.length >= 17) room.boundary = dec[16];
                console.log(`[LOBBY] room#${room.id} ChangeBoundary = ${room.boundary}`);
                console.log(`[LOBBY]   raw payload (${rawPL.length}b): ${rawPL.toString('hex')}`);

                await sendPacket(socket, ctx, PKT.SA_Room_ChangeBoundary, helpers.buildErrorAck());
                await broadcastRoom(room.id, PKT.SN_Room_Info, buildRoomInfoPayload(room), socket);
                break;
            }

            // CQ_Room_ChangePassword (0x22021B) — sub_1013C600 SendChangePassword reverse:
            //   Total: 28 byte = 16 hdr + 12 byte payload
            //     payload[ 0]    = u8 isLocked (cache[32] = a10)
            //     payload[ 1..11] = ascii password (sprintf'lı, null-term, max 10 char + null)
            //
            // ÖNEMLİ: Bu paket SADECE password (kilit) değiştirir, başka ROOM AYARI
            // değiştirmez. Ama "ChangeRule.confirm" UI butonu sub_1013CD90'ı çağırır
            // ve o da SIRAYLA 5 paket gönderir:
            //   1. CQ_Room_ChangeMapInfo (0x220221, 14b)  — map + score + clan
            //   2. CQ_Room_ChangeBoundary (0x220211, 1b)  — level limiti
            //   3. CQ_Room_ChangeName (0x220218, 58b)     — yeni isim utf-8
            //   4. CQ_Room_ChangeOption (0x220215, 3b)    — friendlyFire + autoBalance
            //   5. CQ_Room_ChangePassword (0x22021B, 12b) — kilit + password
            // Her paketin handler'ı kendi field'ını günceller. Eğer log'da sadece
            // ChangePassword görünüyorsa diğer 4'ü ya client göndermedi ya da
            // dispatcher tanımıyor (opcode mismatch). Raw payload aşağıda.
            case PKT.CQ_Room_ChangePassword: {
                const room = rooms.get(ctx.roomId);
                if (!room || room.hostUserId !== ctx.userId) break;
                const rawPL = dec.slice(16);
                if (dec.length >= 17) {
                    const isLocked = dec[16] !== 0;
                    let pwd = '';
                    if (isLocked && dec.length > 17) {
                        let end = 17;
                        while (end < Math.min(dec.length, 17 + 11) && dec[end] !== 0) end++;
                        pwd = dec.slice(17, end).toString('utf8');
                    }
                    room.password = isLocked ? pwd : null;
                    console.log(`[LOBBY] room#${room.id} ChangePassword locked=${isLocked} pw="${pwd}"`);
                }
                console.log(`[LOBBY]   raw payload (${rawPL.length}b): ${rawPL.toString('hex')}`);

                await sendPacket(socket, ctx, PKT.SA_Room_ChangePassword, helpers.buildErrorAck());
                await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room);
                break;
            }

            // ---- TEAM ----
            // CQ_Team_Change (0x220311) NRoom alt-submodule. Payload[0..1] u16 = target team.
            // Client EXPLICIT bir takım istiyor ("ben 2'ye geçmek istiyorum"), toggle değil.
            // SA_Team_Change ack'i + SN_Team_Change broadcast → herkesin UI'sı güncellensin.
            // Sonra UserList yeniden gönder ki squad render güncel team ile yeniden çalışsın.
            case PKT.CQ_Team_Change: {
                const room = rooms.get(ctx.roomId);
                if (!room) break;
                const me = room.players.get(ctx.userId);
                if (!me) break;
                const targetTeam = dec.length >= 18 ? dec.readUInt16LE(16) : (me.team === 1 ? 2 : 1);
                me.team   = targetTeam;
                ctx.team  = targetTeam;
                console.log(`[LOBBY] team change ${ctx.username} → team ${targetTeam}`);

                const p = Buffer.alloc(8);
                p.writeUInt32LE(ctx.userId, 0);
                p.writeUInt8  (targetTeam,  4);
                await sendPacket   (socket, ctx, PKT.SA_Team_Change, p);
                await broadcastRoom(room.id, PKT.SN_Team_Change, p);
                // Squad listesi yeniden çizilsin (parser team check tekrar çalışsın)
                await broadcastRoom(room.id, PKT.SN_Room_UserList, buildRoomUserListPayload(room));
                break;
            }

            // CN_Play_StartButton (0x222103) — F5 Hazır / Başlat tıklandığında gelir.
            // Server reaksiyonu (KRİTİK SIRA):
            //   1. Dedi socket'ine SN_BaseRoomInfo + SN_BaseUserList gönder
            //      → TheRawServer "expected client list"e bu user'ı ekler.
            //   2. Gönderene SN_Hosting_HostConnect → client dedi'ye bağlanır.
            //   3. Client TheRawServer'a bağlanınca OnAddClient lookup yapar:
            //      bizim adımım 1'de gönderdiğimiz user ID listede VARSA kabul,
            //      yoksa "ServerConnectionMgr::OnAddClient() 2" BAN.
            //
            // Reverse: GameServer.dll sub_100D3600 (CHermitProcessMsg::HandleMatchup)
            //   case 1 (opcode 0x222112): packet[18] u16 = userId → lookup table
            //   sub_10085CF0 (OnAddClient): this[9] != lookup → BAN
            case PKT.CN_Play_StartButton: {
                const room = rooms.get(ctx.roomId);
                if (!room) break;

                // 1) Dedi'ye SN_BaseRoomInfo + SN_BaseUserList — expected client list set
                const dediEntry = [...dedicateds.entries()].find(([sock, d]) => true); // ilk dedi (test için)
                if (dediEntry) {
                    const [dediSocket, dedi] = dediEntry;
                    const dediCtx = clients.get(dediSocket);
                    if (dediCtx) {
                        dedi.roomId = room.id;
                        console.log(`[LOBBY] CN_StartButton: dedi'ye expected user list gönderiliyor (room=${room.id}, players=${room.players.size})`);
                        try {
                            await sendPacket(dediSocket, dediCtx, PKT.SN_Play_BaseRoomInfo, buildBaseRoomInfoPayload(room));
                            await sendPacket(dediSocket, dediCtx, PKT.SN_Play_BaseUserList, buildBaseUserListPayload(room));
                            // GERİ DÖNÜŞ: 0x230103 deneyi dedi state machine'i bozdu (Ready2/RoundStart
                            // gelmedi). ChangeRound (0x222122) ile state machine düzgün ilerliyor.
                            // Kazanma sorunu BattleInfo roundCount=99 ile çözülecek umuduyla.
                            try {
                                await sendPacket(dediSocket, dediCtx, PKT.SN_Play_BattleInfo, buildBattleInfoPayload(room));
                                console.log(`[LOBBY] DEDI: SN_Play_BattleInfo gönderildi (roundCount=99 zorlandı)`);
                                await sendPacket(dediSocket, dediCtx, 0x222122, Buffer.from([0x00]));
                                console.log(`[LOBBY] DEDI: 0x222122 ChangeRound gönderildi`);
                                await sendPacket(dediSocket, dediCtx, 0x222213, Buffer.from([0x01, 0x00]));
                                console.log(`[LOBBY] DEDI: 0x222213 gönderildi`);
                                await sendPacket(dediSocket, dediCtx, 0x222121, Buffer.from([0x01, 0x00, 0x01]));
                                console.log(`[LOBBY] DEDI: 0x222121 gönderildi`);

                                // ★★★ KRİTİK PROMOTION MESAJI — DELAYED ★★★
                                // 0x230152 = MATCH-START / SPAWN-PROMOTE — GameServer.dll sub_100D28C0 case 2294098.
                                // Server bu paketi alınca dword_101D9374 (CPlayerObj listesi) için DoRespawn-all loop
                                // çalıştırır. AMA client UDP→dedi handshake + CPlayerObj creation BU NOKTADA bitmiş
                                // OLMAZ — paket boş listede dönerdi (canlı debug 2026-04-30 doğrulandı).
                                //
                                // FIX: setTimeout ile gecikmeli gönder. Client SN_Hosting_HostConnect alıp
                                // dedi'ye UDP-handshake yapması (~1-2s) + engine'in OnClientEnterWorld → CreatePlayer
                                // tamamlaması beklenmeli. 5 saniye güvenli upper bound.
                                //
                                // Format: 8 byte sıfır payload (parser a2+16 word + a2+18 dword sıfır check).
                                setTimeout(async () => {
                                    try {
                                        if (dediSocket.destroyed) {
                                            console.warn(`[LOBBY] DEDI: 0x230152/0x230151 delayed send aborted (dedi socket dropped)`);
                                            return;
                                        }
                                        // 0x230152 = MASS DoRespawn (state=Playing + DoRespawn-all loop)
                                        await sendPacket(dediSocket, dediCtx, 0x230152, Buffer.alloc(8));
                                        console.log(`[LOBBY] DEDI: 0x230152 (DELAYED MATCH-START / DoRespawn-all) gönderildi ★`);

                                        // 0x230151 (PER-USER SPAWN) — sub_10058CC0 → RTDynamicCast(CPlayerObj) → vtable[57](team)
                                        // → sub_100D1CA0(GameState) → sub_100657F0(player, axis, pos, rot) → MID 0xE6/0x0B spawn-at-point.
                                        // Crash root cause (FIXED via PATCH 3): sub_100D1CA0, config[+0x264] != gameState.vtable[2]()
                                        // olunca NULL dönüyordu → ebx=0 → [0+24*team+0x1A0] AV → 233MB dump.
                                        // GameServer.dll'de sub_100D1CA0 setnz cl NOP'landı, daima a1 döner.
                                        for (const [, pl] of room.players) {
                                            const pc = clients.get(pl.socket);
                                            if (!pc || pc.userId == null) continue;
                                            const vIdx = pc.userId & 0xFFFF;
                                            const p = Buffer.alloc(2);
                                            p.writeUInt16LE(vIdx, 0);
                                            await sendPacket(dediSocket, dediCtx, 0x230151, p);
                                            console.log(`[LOBBY] DEDI: 0x230151 (PER-USER SPAWN) virtualIndex=0x${vIdx.toString(16)} (${pc.username}) gönderildi ★`);
                                        }
                                    } catch (e) {
                                        console.warn('[LOBBY] delayed 0x230152/0x230151 fail:', e.message);
                                    }
                                }, 5000);
                                console.log(`[LOBBY] DEDI: 0x230152 + 0x230151 5s sonra gönderilecek (client UDP handshake için bekle)`);
                            } catch (e) { console.warn('[LOBBY] dedi spawn-trigger fail:', e.message); }
                        } catch (e) { console.warn('[LOBBY] dedi notify fail:', e.message); }
                    }
                }

                // SN_GameFinalResult (match-end result screen) BURADA gönderilmemeli —
                // SN_Hosting_HostConnect'ten ÖNCE gelirse client Result ekranına geçer ve
                // OnRecvSNHostConnect handler'ı ateşlemez → client dedi'ye UDP atmaz →
                // OnClientEnterWorld yok → CPlayerObj yaratılmaz → dword_101D9374 boş kalır →
                // 0x230152 DoRespawn-all loop boş dönüyor → spawn fail (canlı debug 2026-04-30 doğrulandı).
                // Result screen ayrı bir tetikleyici ile (gerçek match end) gönderilmeli.

                // 2) Gönderene SN_HostConnect (port + ip)
                const ip   = dediEntry ? dediEntry[1].ip   : '127.0.0.1';
                const port = dediEntry ? dediEntry[1].port : 27888;
                console.log(`[LOBBY] CN_StartButton from ${ctx.username} → SN_HostConnect ${ip}:${port}`);
                await send_SN_Hosting_HostConnect(socket, ctx, ip, port);

                // 3) SN_BattleStart — SADECE client'a (dedi'ye GÖNDERME, BAN sebebi olabilir).
                // TheRawServer BattleStart alınca expected user list'i clear ediyor olabilir →
                // sonradan client connect → lookup boş → "OnAddClient() 2" BAN.
                {
                    const bp = Buffer.alloc(32);
                    bp.writeUInt16LE(port, 0);
                    bp.write(ip, 3, Math.min(ip.length, 15), 'ascii');
                    await sendPacket(socket, ctx, PKT.SN_Hosting_BattleStart, bp);
                    room.status = 'playing';
                }

                // NOT: 0x230104 (SN_Revive), 0x230124 (SN_Kill), 0x220510 (NN_BattleTeamRadio)
                // gerçek game-event paketleri — periodic heartbeat değil. Bu yüzden burada
                // tetiklemek YANLIŞ olurdu (her tick "biri kill yaptı" notify'ı atılırdı).
                // Onlar dedi'den lobby'ye gelir, lobby de match içindeki diğer client'lara relay eder.
                break;
            }

            // CN_Play_Ping (0x222141) — D187 client periodic ping triplet (2026-04-30 capture).
            // Payload: 8B = "03 00 00 00 [4-byte LE timestamp]"
            // Server cevabı: 0x222142 (30B, timestamp echo) + 0x222143 (6B zeros).
            // Bizim eski lobby YOKTU; client D187'de bunu gönderiyor, server zamanlama ack veriyor.
            // Camera bind'le doğrudan alaka belirsiz ama ping cevabı vermek iyi davranış.
            case PKT.CN_Play_Ping: {
                const payload = dec.slice(16);
                const tag = payload.readUInt32LE(0);          // 0x00000003
                const ts  = payload.readUInt32LE(4);          // client timestamp
                console.log(`[LOBBY] CN_Play_Ping ${ctx.username} tag=0x${tag.toString(16)} ts=0x${ts.toString(16)}`);

                // 0x222142 — 30B payload echoes timestamp at offset 10
                const ack = Buffer.alloc(30);
                ack.writeUInt32LE(tag, 0);
                ack.writeUInt32LE(ts,  10);
                await sendPacket(socket, ctx, PKT.SA_Play_Ping, ack);

                // 0x222143 — 6B zeros (basit ack)
                await sendPacket(socket, ctx, PKT.SN_Play_PingExtra, Buffer.alloc(6));
                break;
            }

            // CN_Team_Exchange (0x220314) — auto-balance/team-swap.
            // Payload boş (16 byte = sadece header). UI "GameRoomList.squadChange"
            // butonundan tetikleniyor: "Takımları Eşitle / Takasla".
            // Davranış: tüm oyuncuların takımını swap et (team 1 ↔ team 2).
            // Sonra SN_Room_UserList ile herkesi güncelle.
            case PKT.CN_Team_Exchange: {
                const room = rooms.get(ctx.roomId);
                if (!room) break;
                let swapped = 0;
                for (const [, pl] of room.players) {
                    if (pl.team === 1) { pl.team = 2; swapped++; }
                    else if (pl.team === 2) { pl.team = 1; swapped++; }
                }
                console.log(`[LOBBY] room#${room.id} TeamExchange: ${swapped} oyuncu takım takasladı`);

                // SA + SN broadcast (herkes UserList'i yeniden render etsin)
                await sendPacket(socket, ctx, PKT.SA_Team_Exchange, helpers.buildErrorAck());
                await broadcastRoom(room.id, PKT.SN_Team_Exchange, helpers.buildErrorAck());
                await broadcastRoom(room.id, PKT.SN_Room_UserList, buildRoomUserListPayload(room));
                break;
            }

            case PKT.CQ_Team_ExchangeTeam: {
                const room = rooms.get(ctx.roomId);
                if (!room) break;
                for (const [, pl] of room.players) pl.team = pl.team === 1 ? 2 : 1;

                const p = Buffer.alloc(4);
                p.writeUInt32LE(room.id, 0);
                await sendPacket(socket, ctx, PKT.SA_Team_ExchangeTeam, p);
                await broadcastRoom(room.id, PKT.SN_Team_ExchangeTeam, buildRoomUserListPayload(room));
                break;
            }

            // ---- PLAY ----
            case PKT.CQ_Play_Ready: {
                const room = rooms.get(ctx.roomId);
                if (!room) break;
                const me = room.players.get(ctx.userId);
                if (!me) break;
                me.ready = !me.ready;
                ctx.ready = me.ready;
                await broadcastRoom(room.id, PKT.SN_Play_BaseUserList, buildRoomUserListPayload(room));
                break;
            }

            case PKT.CQ_Play_Start: {
                const room = rooms.get(ctx.roomId);
                if (!room || room.hostUserId !== ctx.userId) break;
                room.status = 'playing';

                const dedi = [...dedicateds.values()].find(d => d.roomId === room.id);
                const ip   = dedi ? dedi.ip   : '127.0.0.1';
                const port = dedi ? dedi.port : CONFIG.DEDI_PORT;

                const p = Buffer.alloc(32);
                p.fill(0);
                p.writeUInt16LE(port, 0);
                p.write(ip, 3, 15, 'ascii');
                await broadcastRoom(room.id, PKT.SN_Hosting_BattleStart, p);
                await send_SN_Room_UpdateInfoToChannelUser(room.channelId, room);
                break;
            }

            // (eski stub PKT.CQ_Chat_DevCommand kaldırıldı — gerçek handler
            //  yukarıda CN_Chat_DevCommand case'inde, login + admin komutları)

            // ---- DEDICATED HANDSHAKE ----
            case PKT.CQ_TheRawServer_Connect:
                handleDedicatedConnect(socket, ctx, dec);
                break;

            // ============================================================
            // dedi → lobby notification handlers (deep reverse 2026-04-30).
            // Tüm 0x42xxxx paketleri TheRawServer'dan geliyor — her birinin
            // formatı GameServer.dll içinde reverse'lendi.
            // ============================================================

            // 0x420203 — handshake sonrası ilk "ready" sinyali (16 byte = sadece header).
            // Builder: GameServer.dll sub_100D1FA0 (mov [ecx+0Ch], 420203h; mov [ecx+6], 16).
            // Lobby tarafı: sadece log, payload yok, cevap yok.
            case PKT.SN_TheRawServer_HandshakeAck: {  // = 0x420203
                console.log(`[DEDI→lobby] HandshakeAck (0x420203) — ready signal`);
                break;
            }

            // 0x420205 — state=Playing achieved + virtualIndex (18 byte).
            // Builder: 0x10083655/3b32/8553d/85fc3 (4 farklı yer, kullanım context'ine göre).
            // Format: payload[0..1] u16 virtualIndex (LE).
            // Canlı debug 2026-04-30: 0x230152 (DoRespawn-all) işlendikten ve state=Playing
            // (sub_100CCA10(state=4)) set olduktan sonra dedi bu paketi yolluyor.
            case PKT.SN_TheRawServer_StatePlaying: {  // = 0x420205
                const payload = dec.slice(16);
                const vIdx = payload.length >= 2 ? payload.readUInt16LE(0) : -1;
                console.log(`[DEDI→lobby] StatePlaying (0x420205) virtualIndex=0x${vIdx.toString(16)} → server state=Playing`);
                break;
            }

            // 0x420206 — handshake sonrası 2. ready sinyali + virtualIndex (18 byte).
            // Builder: 0x10083685/3b52/847b1.
            // Format: payload[0..1] u16 virtualIndex (LE).
            case PKT.SN_TheRawServer_HandshakeAck2: {  // = 0x420206
                const payload = dec.slice(16);
                const vIdx = payload.length >= 2 ? payload.readUInt16LE(0) : -1;
                console.log(`[DEDI→lobby] HandshakeAck2 (0x420206) virtualIndex=0x${vIdx.toString(16)}`);
                break;
            }

            // 0x420208 — generic per-user notification (18 byte).
            // Builder: sub_10083630 (mov [eax+0Ch], 420208h; mov [eax+6], 18).
            // Format: payload[0..1] u16 virtualIndex (LE).
            // Eski davranış: echo back. Sessiz bırakınca BAN — echo gerekli.
            case PKT.SN_TheRawServer_Notify: {  // = 0x420208
                const payload = dec.slice(16);
                const vIdx = payload.length >= 2 ? payload.readUInt16LE(0) : -1;
                console.log(`[DEDI→lobby] Notify (0x420208) virtualIndex=0x${vIdx.toString(16)} — echo back`);
                await sendPacket(socket, ctx, PKT.SN_TheRawServer_Notify, payload);
                break;
            }

            // 0x230103 — dedi engine task: DoRespawn notification (19 byte).
            // Builder: sub_100CC270 (DoRespawn) — engine task queue'ya enqueue edilen
            // spawn task'ın broadcast'ı. Lobby'ye TCP üzerinden bildirim olarak ulaşıyor.
            // Format: packet[0xC]=0x230103, packet[6]=19, packet[0x10..0x11]=u16 virtualIndex,
            //         packet[0x12]=u8 doRespawnFlag (0 normal, 1 SN_Revive).
            // Reverse: sub_100CC270 disasm onaylı (operator new(0x400) → set fields → enqueue).
            // Lobby: sadece log, cevap yok (engine task'ı sürdürür).
            case PKT.SN_TheRawServer_DoRespawnTask: {  // = 0x230103
                const payload = dec.slice(16);
                const vIdx = payload.length >= 2 ? payload.readUInt16LE(0) : -1;
                const flag = payload.length >= 3 ? payload[2] : -1;
                console.log(`[DEDI→lobby] DoRespawnTask (0x230103) virtualIndex=0x${vIdx.toString(16)} flag=${flag} — engine task queued`);
                break;
            }

            // 0x230151 — dedi case 2294097 (sub_10058CC0) — SN_RoundStart per-user.
            // Bu opcode normalde lobby → dedi yönünde GIDIYOR. Eğer dedi'den lobby'ye
            // GELIRSE bu bir relay/echo (yan etki). Sessiz log yeterli.
            case PKT.SN_RoundStart: {  // = 0x230151
                const payload = dec.slice(16);
                console.log(`[DEDI→lobby] SN_RoundStart (0x230151) ${payload.length}B: ${payload.toString('hex')}`);
                break;
            }

            // 0x230111 — dedi → lobby: RoundEnd (state=5=EndingRound) notify.
            // Reverse: sub_100CD7D0 — round timer expire / "Host EServerGameState_EndingRound".
            // Format: 16 byte sadece header, payload yok.
            // Bizim için ÖNEMLİ İŞARET: bu paket gelirse dedi round'u bitirmiş demek
            // → spawn time penceresi kapanmış olabilir. ⚠
            case PKT.SN_TheRawServer_RoundEnd: {  // = 0x230111
                console.log(`[DEDI→lobby] ⚠ RoundEnd (0x230111) — dedi state=EndingRound, round timer expired`);
                break;
            }

            default: {
                // Fallback: tanınan paket ID'si için ack-only cevap.
                // Friend / Mail / Tournament / Guild / Marble — INVALID OPCODE çıkmasın.
                const ackOpcode = helpers.CQ_TO_SA_ACK[opcode];
                if (ackOpcode) {
                    await sendPacket(socket, ctx, ackOpcode, helpers.buildErrorAck());
                    console.log(`[LOBBY] ack-only handler 0x${opcode.toString(16)} → 0x${ackOpcode.toString(16)}`);
                } else if (helpers.SILENT_OPCODES.has(opcode)) {
                    // Sessizce kabul (CN_*/notify paketler)
                } else {
                    console.log(`[LOBBY] unknown 0x${opcode.toString(16)} payload: ${dec.slice(16, Math.min(dec.length, 64)).toString('hex')}`);
                }
            }
        }
    } catch (err) {
        console.error(`[LOBBY] handler error 0x${opcode.toString(16)}:`, err.message);
    }
}

// --------------------------------------------------------------------------
// SOCKET → PAKET PARÇALAMA + KEY ÇÖZME
// --------------------------------------------------------------------------

// Header'sız size'ı encrypted modda öğrenmek için minimal header decrypt.
// Sadece [6..7] (size) BE u16'yı decrypt edip LE int olarak döndürür.
function peekEncryptedSize(buf, keyByte) {
    if (buf.length < 16) return -1;
    const b6 = keyByte ^ buf[6] ^ (crcTable[6] & 0xFF);
    const b7 = keyByte ^ buf[7] ^ (crcTable[7] & 0xFF);
    return (b6 << 8) | b7;   // BE → integer
}

async function onSocketData(socket, data) {
    const ctx = clients.get(socket);
    if (!ctx) return;

    // Buffer + birikmiş veriyle birleştir
    let buffer = ctx.recvBuffer ? Buffer.concat([ctx.recvBuffer, data]) : data;
    ctx.recvBuffer = null;
    if (buffer.length < 16) { ctx.recvBuffer = buffer; return; }

    // Mode tespit (sadece ilk packet için).
    //   - sex.exe ve TheRaw.exe (yeni gerçek client) PLAIN gönderir; CRC alanı
    //     sex.exe'de sabit 0x117b5a78, TheRaw.exe'de farklı (uninitialized) olabilir.
    //   - TheRawServer.exe (dedi) ENCRYPTED gönderir.
    // Sıra:
    //   1) ENCRYPTED brute-force dene — CRC32 validation ile yanlış pozitif yok.
    //      Başarılı → ENCRYPTED.
    //   2) Başarısız → PLAIN varsay (size [6..7] LE makulse).
    //   3) İkisi de başarısız → reddet.
    // Dedi vs Client ayrımı handshake opcode'undan sonra (processPacket içinde
    // 0x410101 gelirse handleDedicatedConnect ctx.isDedicated = true set eder).
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
            console.log(`[LOBBY ${ctx.id.slice(0,6)}] mode = ENCRYPTED, keyByte=0x${keyFound.toString(16)} (TheRaw.exe / TheRawServer.exe)`);
        } else {
            const plainSize = buffer.readUInt16LE(6);
            if (plainSize >= 16 && plainSize <= 0x400) {
                ctx.encrypted = false;
                console.log(`[LOBBY ${ctx.id.slice(0,6)}] mode = PLAIN (size=${plainSize})`);
            } else {
                console.warn(`[LOBBY ${ctx.id.slice(0,6)}] mode tespit edilemedi (plainSize=${plainSize}, encrypted brute-force fail) — kapatılıyor`);
                console.warn(`[LOBBY ${ctx.id.slice(0,6)}] ilk 32 byte: ${buffer.slice(0, 32).toString('hex')}`);
                socket.destroy();
                return;
            }
        }
    }

    let off = 0;
    while (off + 16 <= buffer.length) {
        let size, slice;
        if (ctx.encrypted) {
            // Hermit cipher key paketten pakete değişebiliyor (dedi sequence-rotation
            // veya farklı schedule). Cached keyByte'ı önce dene, başarısızsa 0..255
            // brute-force yap (eski sex.js mantığı). Başarılı key cache'lenir.
            const remaining = buffer.slice(off);
            slice = null;
            // 1) cached key
            const cachedSize = peekEncryptedSize(remaining, ctx.keyByte);
            if (cachedSize >= 16 && cachedSize <= 0x400 && off + cachedSize <= buffer.length) {
                const tryDec = decryptPacket(remaining.slice(0, cachedSize), ctx.keyByte);
                if (tryDec) { slice = tryDec; size = cachedSize; }
            }
            // 2) brute-force fallback
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
                // Buraya düşmek = ya partial packet (daha veri lazım) ya da kötü paket.
                // Buffer'da yer fazla ama hiçbir key çözmüyorsa: socket'i kapat.
                if (buffer.length - off >= 0x400) {
                    console.warn(`[LOBBY ${ctx.id.slice(0,6)}] decrypt fail @off=${off} bufLen=${buffer.length}`);
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

    // Kalan tam packet olmayan byte'ları sakla
    if (off < buffer.length) ctx.recvBuffer = buffer.slice(off);
}

// --------------------------------------------------------------------------
// TCP SERVER
// --------------------------------------------------------------------------

const server = net.createServer({ allowHalfOpen: false }, socket => {
    // *** verbose connection log — TheRawServer connection debug için ***
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    const local  = `${socket.localAddress}:${socket.localPort}`;
    console.log(`[LOBBY:CONN] >>> NEW TCP CONNECTION from ${remote} → ${local}`);

    const ctx = createClient(socket);

    socket.on('data',  data => {
        console.log(`[LOBBY:DATA] ${ctx.id.slice(0,6)} ${remote} ${data.length} byte: ${data.slice(0, Math.min(data.length, 32)).toString('hex')}${data.length > 32 ? '...' : ''}`);
        onSocketData(socket, data);
    });
    socket.on('close', hadError => {
        console.log(`[LOBBY:CLOSE] ${ctx.id.slice(0,6)} ${remote} hadError=${hadError}`);
        destroyClient(socket);
    });
    socket.on('error', err => {
        console.error(`[LOBBY:ERR] ${ctx.id.slice(0,6)} ${remote}: ${err.message}`);
        destroyClient(socket);
    });
    socket.on('end',  () => console.log(`[LOBBY:END] ${ctx.id.slice(0,6)} ${remote}`));
    socket.on('timeout', () => console.log(`[LOBBY:TIMEOUT] ${ctx.id.slice(0,6)} ${remote}`));
});

server.on('error', err => console.error('[LOBBY] server error:', err.message));

server.listen(CONFIG.PORT, CONFIG.HOST, () => {
    console.log('=================================');
    console.log(' S2 LOBBY SERVER');
    console.log(`   listen    ${CONFIG.HOST}:${CONFIG.PORT}     (sex.exe / TheRaw.exe / TheRawServer.exe)`);
    console.log(`   dedi UDP  ${CONFIG.HOST}:${CONFIG.DEDI_PORT}     (TheRaw.exe gameplay UDP target)`);
    console.log('=================================');
    console.log(' MAP TEST KOMUTLARI (terminale yaz):');
    console.log('   next           sonraki map (Map.csv sırası)');
    console.log('   prev           önceki map');
    console.log('   first          listenin başı');
    console.log('   last           listenin sonu');
    console.log('   map <id>       belirli mapId set et (örn: map 10018)');
    console.log('   current        şu anki mapId\'i göster');
    console.log('   good / bad / skip   sonucu kaydet + sonraki map\'e geç');
    console.log('   results        kaydettiğin sonuçları göster');
    console.log('   help           bu listeyi tekrar göster');
    console.log('=================================');
});

// ==========================================================================
// MAP TEST KOMUT INTERFACE'i
// Terminal stdin'inden komut okur, default mapId'i değiştirir.
// Sonuçları map-test-results.txt'e ekler.
// ==========================================================================
{
    const fs   = require('fs');
    const path = require('path');
    const RESULTS_FILE = path.resolve(__dirname, '..', 'map-test-results.txt');

    // Map.csv'den tüm map ID'lerini sırayla al (numerik artan).
    items.loadMaps();
    const allMapIds = [...items.loadMaps().keys()].sort((a, b) => a - b);

    // Şu anki test edilen index.
    let curIdx = 0;
    const startId = parseInt(process.env.S2_DEFAULT_MAP || '10006', 10);
    const startIdx = allMapIds.indexOf(startId);
    if (startIdx >= 0) curIdx = startIdx;

    function setMap(id) {
        process.env.S2_DEFAULT_MAP = String(id);
        const meta = items.getMap(id);
        const total = allMapIds.length;
        const pos   = allMapIds.indexOf(id) + 1;
        console.log(`\n[MAP-TEST] >>> mapId=${id}  ${meta?meta.name+' ('+meta.mode+', rule='+meta.ruleIndex+')':'??'}  [${pos}/${total}]`);
        console.log(`[MAP-TEST]     Şimdi client'tan oda kur, START bas. Popup geliyorsa 'bad', gelmiyorsa 'good' yaz.\n`);
    }

    function logResult(verdict) {
        const id = allMapIds[curIdx];
        const meta = items.getMap(id);
        const line = `${id},${(meta?meta.name:'?').replace(/,/g,';')},${meta?meta.mode:'?'},${verdict}\n`;
        try {
            fs.appendFileSync(RESULTS_FILE, line);
            console.log(`[MAP-TEST] kaydedildi: ${line.trim()}`);
        } catch (e) {
            console.warn(`[MAP-TEST] kayıt hatası: ${e.message}`);
        }
    }

    function showResults() {
        try {
            const txt = fs.readFileSync(RESULTS_FILE, 'utf8');
            const lines = txt.trim().split('\n');
            const good = lines.filter(l => l.endsWith(',GOOD'));
            const bad  = lines.filter(l => l.endsWith(',BAD'));
            console.log(`\n[MAP-TEST] === SONUÇLAR (${RESULTS_FILE}) ===`);
            console.log(`[MAP-TEST] Toplam test: ${lines.length}, GOOD: ${good.length}, BAD: ${bad.length}`);
            if (good.length) {
                console.log(`[MAP-TEST] GOOD ID'ler: ${good.map(l => l.split(',')[0]).join(', ')}`);
            }
            console.log('');
        } catch (e) {
            console.log(`[MAP-TEST] henüz sonuç yok (${RESULTS_FILE} oluşturulmadı).`);
        }
    }

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => {
        const cmd = chunk.toString().trim();
        if (!cmd) return;
        const [op, arg] = cmd.split(/\s+/);

        switch (op) {
            case 'next':
                curIdx = Math.min(curIdx + 1, allMapIds.length - 1);
                setMap(allMapIds[curIdx]);
                break;
            case 'prev':
                curIdx = Math.max(curIdx - 1, 0);
                setMap(allMapIds[curIdx]);
                break;
            case 'first':
                curIdx = 0;
                setMap(allMapIds[curIdx]);
                break;
            case 'last':
                curIdx = allMapIds.length - 1;
                setMap(allMapIds[curIdx]);
                break;
            case 'map': {
                const id = parseInt(arg, 10);
                const idx = allMapIds.indexOf(id);
                if (idx < 0) { console.log(`[MAP-TEST] ${id} Map.csv'de yok`); break; }
                curIdx = idx;
                setMap(id);
                break;
            }
            case 'current':
                setMap(allMapIds[curIdx]);
                break;
            case 'good':
                logResult('GOOD');
                curIdx = Math.min(curIdx + 1, allMapIds.length - 1);
                setMap(allMapIds[curIdx]);
                break;
            case 'bad':
                logResult('BAD');
                curIdx = Math.min(curIdx + 1, allMapIds.length - 1);
                setMap(allMapIds[curIdx]);
                break;
            case 'skip':
                logResult('SKIP');
                curIdx = Math.min(curIdx + 1, allMapIds.length - 1);
                setMap(allMapIds[curIdx]);
                break;
            case 'results':
                showResults();
                break;
            case 'help':
                console.log('Komutlar: next, prev, first, last, map <id>, current, good, bad, skip, results, help');
                break;
            default:
                console.log(`[MAP-TEST] bilinmeyen komut: ${op}  (yardım için 'help')`);
        }
    });
}

