'use strict';
// Hermit decoder for LOBBY capture — focused on opcode sequence + special packets

const fs = require('fs');
const path = require('path');

const crcTable = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        t[n] = c >>> 0;
    }
    return t;
})();

function decryptPacket(buf, keyByte) {
    if (buf.length < 16) return null;
    const out = Buffer.from(buf);
    let crc = 0xFFFFFFFF;
    for (let i = 4; i < 16; i++) {
        const orig = buf[i];
        out[i] = keyByte ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    out.slice(4, 6).swap16();
    out.slice(6, 8).swap16();
    out.slice(12, 16).swap32();
    const size = out.readUInt16LE(6);
    if (size < 16 || size > buf.length) return null;
    for (let i = 16; i < size; i++) {
        const orig = buf[i];
        out[i] = keyByte ^ orig ^ (crcTable[i] & 0xFF);
        crc = crcTable[(orig ^ (crc & 0xFF)) & 0xFF] ^ (crc >>> 8);
    }
    return { out: out.slice(0, size), size, sequence: out.readUInt16LE(4), opcode: out.readUInt32LE(12) & 0xFFFFFF };
}

function splitTCP(buf, keyByte) {
    const packets = [];
    let off = 0;
    while (off + 16 <= buf.length) {
        const r = decryptPacket(buf.slice(off), keyByte);
        if (!r) break;
        packets.push(r);
        off += r.size;
    }
    return packets;
}

const KEY = 0x0F;
const FULL = fs.readFileSync(path.resolve(__dirname, 'mitm_capture_full.txt'), 'utf8');
const lines = FULL.split(/\r?\n/);

const captures = [];
for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\[(\S+)\]\s+(C→S|S→C)\s+#(\d+)\s+(\d+)B/);
    if (m && i + 1 < lines.length) {
        const hex = lines[i+1].trim();
        if (/^[0-9a-f]+$/.test(hex)) {
            captures.push({ tag: m[1], dir: m[2], idx: m[3], len: parseInt(m[4]), hex });
        }
    }
}

// Known opcodes from our project
const OPCODE_NAMES = {
    0x020080: 'CQ_Heartbeat',
    0x020081: 'SA_HeartbeatAck',
    0x020082: 'CQ_KeepAlive',
    0x020084: 'CQ_KeepAlive2',
    0x110111: 'CQ_JoyGameLogin',
    0x110112: 'SA_JoyGameLogin',
    0x110124: 'CQ_Join',
    0x110125: 'SA_Join',
    0x210101: 'SN_UserInfo',
    0x210103: 'SN_Record',
    0x210105: 'SN_RankingInfo',
    0x210111: 'SN_ItemList',
    0x210113: 'SN_RecordMapList',
    0x210121: 'SN_LockEnd',
    0x210122: 'SN_RecordX',
    0x220101: 'SN_ServerInfo',
    0x220102: 'SN_ChannelList',
    0x220107: 'SN_GroupList',
    0x220108: 'SN_ServerList',
    0x220111: 'CQ_Channel_EnterUser',
    0x220112: 'SA_Channel_EnterUser',
    0x220113: 'SN_Channel_UserList',
    0x220114: 'CQ_Channel_LeaveUser',
    0x220115: 'SA_Channel_LeaveUser',
    0x220131: 'CQ_ServerSelect',
    0x220132: 'SA_ServerSelect',
    0x220201: 'CQ_Room_Create',
    0x220202: 'SA_Room_Create',
    0x220203: 'SN_Room_Info',
    0x220233: 'SN_Room_UserList',
    0x220311: 'CQ_Team_Change',
    0x220312: 'SA_Team_Change',
    0x220313: 'SN_Team_Change',
    0x220401: 'SN_User_State',
    0x220509: 'NN_Chat_BattleAll',
    0x222103: 'CN_Play_StartButton',
    0x222111: 'SN_Play_BaseRoomInfo',
    0x222112: 'SN_Play_BaseUserList',
    0x222113: 'SN_Play_BattleInfo_old',
    0x222114: 'SN_Play_BattleInfo',
    0x222121: 'SN_Play_ExchangeTeam',
    0x222122: 'SN_Play_ExchangeRule',
    0x222213: 'SN_Play_X',
    0x222221: 'SN_GameFinalResult',
    0x230103: 'SN_TheRawServer_DoRespawnTask',
    0x230111: 'SN_TheRawServer_RoundEnd',
    0x230151: 'SN_RoundStart',
    0x230152: 'SN_MassSpawn',
    0x310201: 'SN_Mail_Info',
    0x310301: 'SN_MailGift_Info',
    0x320101: 'SN_Messenger_FriendList',
    0x320213: 'SN_Messenger_X',
    0x360103: 'SN_360103_NEW',  // not in our PacketTypes
    0x420203: 'SN_TheRawServer_HandshakeAck',
    0x420205: 'SN_TheRawServer_StatePlaying',
    0x420206: 'SN_TheRawServer_HandshakeAck2',
    0x420208: 'SN_TheRawServer_Notify',
    0x420303: 'SN_Hosting_HostConnect',
    0x420310: 'SN_Hosting_BattleStart',
    0x420320: 'CN_DEDI_UserExit',
    0x750101: 'CQ_HackShield',
    0x2a0101: 'SN_Achievement_BaseInfo',
};

console.log(`Parsed ${captures.length} TCP records\n`);

// Stage 1: opcode timeline
console.log(`=== OPCODE TIMELINE ===\n`);
const interesting = [];
for (const c of captures) {
    const buf = Buffer.from(c.hex, 'hex');
    const subs = splitTCP(buf, KEY);
    for (const s of subs) {
        const name = OPCODE_NAMES[s.opcode] || '???';
        const arrow = c.dir === 'C→S' ? '→' : '←';
        const tagShort = c.tag.replace(/-c\d+/, '');
        console.log(`[${tagShort.padEnd(5)}] ${arrow} 0x${s.opcode.toString(16).padStart(6,'0')} (${name}) seq=${s.sequence} size=${s.size}`);
        // Capture interesting packets
        if (!OPCODE_NAMES[s.opcode] || ['SN_Hosting_HostConnect','SN_Hosting_BattleStart','SN_Play_BaseRoomInfo','CN_Play_StartButton','SN_RoundStart','SN_MassSpawn'].includes(name)) {
            interesting.push({ ...c, ...s, name, payload: s.out.slice(16) });
        }
    }
}

// FOCUS: opcodes relevant to match start / camera bind
const FOCUS_OPCODES = [0x230104, 0x220510, 0x420303, 0x222111, 0x222112, 0x222114, 0x230124, 0x222141, 0x222142, 0x222143, 0x222131, 0x222132, 0x220319, 0x220223, 0x222104, 0x222102];
console.log(`\n=== FOCUS PACKETS (match start / camera related) ===\n`);
for (const c of captures) {
    const buf = Buffer.from(c.hex, 'hex');
    const subs = splitTCP(buf, KEY);
    for (const s of subs) {
        if (!FOCUS_OPCODES.includes(s.opcode)) continue;
        const opcodeHex = '0x' + s.opcode.toString(16).padStart(6, '0');
        const name = OPCODE_NAMES[s.opcode] || '???';
        const arrow = c.dir === 'C→S' ? '→' : '←';
        const payload = s.out.slice(16);
        const ascii = Array.from(payload).map(b => (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.').join('');
        console.log(`--- ${arrow} ${opcodeHex} (${name}) seq=${s.sequence} size=${s.size} ---`);
        console.log(`payload (${payload.length}B):`);
        // pretty-print hex in 32-byte rows
        for (let i = 0; i < Math.min(payload.length, 256); i += 32) {
            const row = payload.slice(i, i + 32);
            const hex = row.toString('hex').replace(/(.{8})/g, '$1 ').trim();
            const asc = Array.from(row).map(b => (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.').join('');
            console.log(`  ${i.toString(16).padStart(4,'0')}: ${hex.padEnd(72)} ${asc}`);
        }
        if (payload.length > 256) console.log(`  ... (+${payload.length - 256}B)`);
        console.log();
    }
}
