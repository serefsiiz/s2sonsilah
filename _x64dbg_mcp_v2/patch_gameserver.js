// GameServer.dll patches:
//   PATCH 1: NOP DoRespawn [edi+8D4]==0 gate (sub_100CC270 + 0x10)
//     VA 0x100CC280: 74 54 (jz short) -> 90 90 (NOP NOP)
//   PATCH 2: CPlayerObj init writes 8D4=1, 8D5=1 instead of zeros (sub_10069390)
//     VA 0x10069675: imm32 00 00 00 FF (= 0xFF000000) -> 01 01 00 FF (= 0xFF000101)
//     Effect: every fresh CPlayerObj has [+0x8D4]=1 AND [+0x8D5]=1 from creation
//   PATCH 3: NOP setnz cl in sub_100D1CA0 (GameMode mismatch check bypass)
//     VA 0x100D1CBC: 0F 95 C1 (setnz cl) -> 90 90 90 (NOP NOP NOP)
//     Reason: sub_100D1CA0 compares config[+612] vs gameState.vtable[2]() and returns NULL on mismatch.
//     NULL return propagates to sub_10058CC0 as ebx=0, then [0+24*team+0x1A0] AVs → 233MB crash dump.
//     With cl forced to 0 (from xor ecx,ecx earlier), lea eax,[ecx-1]=−1, and eax,esi=esi → returns a1.
//     This unblocks 0x230151 (per-user spawn) which sends MID 0xE6/0x0B spawn-at-point packet.
//
// All patches together: spawn ready flag set on creation + DoRespawn gate bypass + GameMode check bypass.

const fs = require('fs');
const path = require('path');

const DLL_PATH = path.resolve('C:/Users/Akıncı/Desktop/S2SonSilah/Game/GameServer.dll');
const BACKUP   = DLL_PATH + '.bak';

const PATCHES = [
    {
        name : 'DoRespawn 8D4 gate NOP',
        va   : 0x100CC280,
        old  : Buffer.from([0x74, 0x54]),
        new_ : Buffer.from([0x90, 0x90]),
    },
    {
        name : 'CPlayerObj init 8D4=1 8D5=1 8D7=0 (was 0xFF000000, now 0x00000101)',
        va   : 0x10069675,            // imm32 of mov dword [esi+8D4h], imm32
        // Original 0xFF000000: 8D4=0 8D5=0 8D6=0 8D7=0xFF (team=-1=INVALID)
        // We need 8D4=1 (DoRespawn gate), 8D5=1 (extra ready), 8D7=0 (default team=red, valid).
        // 8D7=0xFF was making sub_10058CC0 (0x230151 per-user spawn) early-exit
        // because vtable[57] (team getter) returned 0xFF. With 8D7=0 default, 0x230151
        // fires fully → model load + activate + send spawn-at-point packet → camera bind works.
        // Real team gets set later via sub_10064CA0 when client sends CSA_CLIENTCONNECTION (a4=1 override).
        old  : Buffer.from([0x01, 0x01, 0x00, 0xFF]),    // current state after first patch
        new_ : Buffer.from([0x01, 0x01, 0x00, 0x00]),    // 8D7=0 (default team=0)
    },
    {
        name : 'sub_100D1CA0 GameMode mismatch check bypass (setnz cl -> NOP)',
        va   : 0x100D1CBC,
        // sub_100D1CA0 disasm:
        //   100d1cb8  xor ecx, ecx              ; cl = 0
        //   100d1cba  cmp edi, eax              ; config[+612] vs gameState.vtable[2]()
        //   100d1cbc  setnz cl                  ; ★ patch: NOP this so cl stays 0
        //   100d1cbf  pop edi
        //   100d1cc0  lea eax, [ecx-1]          ; cl=0 → eax = -1
        //   100d1cc3  and eax, esi              ; eax = esi (a1)
        //   100d1cc5  pop esi
        //   100d1cc6  retn
        // Without this patch, mode mismatch returns 0 → sub_10058CC0 ebx=NULL → AV.
        old  : Buffer.from([0x0F, 0x95, 0xC1]),
        new_ : Buffer.from([0x90, 0x90, 0x90]),
    },
];

function readU32LE(buf, off) { return buf.readUInt32LE(off); }
function readU16LE(buf, off) { return buf.readUInt16LE(off); }

function findFileOffset(buf, va) {
    const peOff = readU32LE(buf, 0x3C);
    if (buf.toString('ascii', peOff, peOff + 4) !== 'PE\0\0') {
        throw new Error('not a PE file');
    }
    const optHdrOff = peOff + 24;
    const imageBase = readU32LE(buf, optHdrOff + 28);
    const numSections = readU16LE(buf, peOff + 6);
    const sizeOptHdr = readU16LE(buf, peOff + 20);
    const sectionsOff = optHdrOff + sizeOptHdr;
    const rva = va - imageBase;

    for (let i = 0; i < numSections; i++) {
        const sOff = sectionsOff + i * 40;
        const virtSize = readU32LE(buf, sOff + 8);
        const virtAddr = readU32LE(buf, sOff + 12);
        const rawSize  = readU32LE(buf, sOff + 16);
        const rawAddr  = readU32LE(buf, sOff + 20);
        if (rva >= virtAddr && rva < virtAddr + Math.max(virtSize, rawSize)) {
            return rawAddr + (rva - virtAddr);
        }
    }
    throw new Error(`VA 0x${va.toString(16)} not in any section`);
}

function main() {
    if (!fs.existsSync(DLL_PATH)) {
        console.error(`[patch] DLL not found: ${DLL_PATH}`);
        process.exit(1);
    }

    if (!fs.existsSync(BACKUP)) {
        fs.copyFileSync(DLL_PATH, BACKUP);
        console.log(`[patch] backup written: ${BACKUP}`);
    }

    let buf = fs.readFileSync(DLL_PATH);
    let changed = false;

    for (const p of PATCHES) {
        const fileOff = findFileOffset(buf, p.va);
        const cur = buf.subarray(fileOff, fileOff + p.old.length);
        console.log(`[patch] ${p.name}`);
        console.log(`  VA 0x${p.va.toString(16)} → file offset 0x${fileOff.toString(16)}`);
        console.log(`  current bytes: ${cur.toString('hex')}`);

        if (cur.equals(p.new_)) {
            console.log(`  already patched.`);
            continue;
        }
        if (!cur.equals(p.old)) {
            console.error(`  expected ${p.old.toString('hex')} got ${cur.toString('hex')} — SKIPPED`);
            continue;
        }

        p.new_.copy(buf, fileOff);
        console.log(`  ✓ wrote ${p.new_.toString('hex')}`);
        changed = true;
    }

    if (changed) {
        fs.writeFileSync(DLL_PATH, buf);
        console.log(`[patch] saved ${DLL_PATH}`);
    } else {
        console.log(`[patch] no changes needed.`);
    }
}

main();
