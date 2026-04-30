'use strict';
// GameClient.dll vanilla vs D187 byte diff.
// Output: list of (file_offset, vanilla_bytes, d187_bytes) regions.

const fs = require('fs');

const A = fs.readFileSync('C:/Users/Akıncı/Desktop/S2SonSilah/Game/GameClient.dll');
const B = fs.readFileSync('C:/Program Files/S2/Game/GameClient.dll');

if (A.length !== B.length) { console.log(`SIZE MISMATCH: ${A.length} vs ${B.length}`); process.exit(1); }

console.log(`Comparing ${A.length} bytes...\n`);

// Parse PE to get section info — needed to translate file offset → VA
function parsePE(buf) {
    const peOff = buf.readUInt32LE(0x3C);
    if (buf.toString('ascii', peOff, peOff + 4) !== 'PE\0\0') throw new Error('not PE');
    const optHdrOff  = peOff + 24;
    const imageBase  = buf.readUInt32LE(optHdrOff + 28);
    const numSections = buf.readUInt16LE(peOff + 6);
    const sizeOptHdr  = buf.readUInt16LE(peOff + 20);
    const sectionsOff = optHdrOff + sizeOptHdr;
    const sections = [];
    for (let i = 0; i < numSections; i++) {
        const sOff = sectionsOff + i * 40;
        const name = buf.toString('ascii', sOff, sOff + 8).replace(/\0.*$/, '');
        const virtSize = buf.readUInt32LE(sOff + 8);
        const virtAddr = buf.readUInt32LE(sOff + 12);
        const rawSize  = buf.readUInt32LE(sOff + 16);
        const rawAddr  = buf.readUInt32LE(sOff + 20);
        const flags    = buf.readUInt32LE(sOff + 36);
        sections.push({ name, virtAddr, virtSize, rawAddr, rawSize, flags });
    }
    return { imageBase, sections };
}

const pe = parsePE(A);
console.log(`ImageBase: 0x${pe.imageBase.toString(16)}`);
console.log(`Sections:`);
for (const s of pe.sections) {
    const exec = (s.flags & 0x20000000) ? ' EXEC' : '';
    console.log(`  ${s.name.padEnd(8)} VA=0x${(pe.imageBase + s.virtAddr).toString(16)} rawOff=0x${s.rawAddr.toString(16)} size=0x${s.rawSize.toString(16)}${exec}`);
}

function fileOffsetToVA(off) {
    for (const s of pe.sections) {
        if (off >= s.rawAddr && off < s.rawAddr + s.rawSize) {
            return pe.imageBase + s.virtAddr + (off - s.rawAddr);
        }
    }
    return null;
}

// Walk byte-by-byte, group consecutive differences into "regions" (within ~32 byte gap)
console.log(`\n=== DIFF REGIONS ===\n`);
const regions = [];
let cur = null;
const GAP_THRESHOLD = 16; // merge differences within 16 bytes
for (let i = 0; i < A.length; i++) {
    if (A[i] !== B[i]) {
        if (cur && i - cur.lastDiffOff <= GAP_THRESHOLD) {
            cur.end = i;
            cur.lastDiffOff = i;
        } else {
            cur = { start: i, end: i, lastDiffOff: i };
            regions.push(cur);
        }
    }
}

console.log(`Found ${regions.length} diff regions\n`);
for (const r of regions) {
    const len = r.end - r.start + 1;
    const va = fileOffsetToVA(r.start);
    const vaStr = va !== null ? `VA=0x${va.toString(16).padStart(8, '0')}` : 'VA=(unknown section)';
    const oldBytes = A.slice(r.start, r.end + 1).toString('hex');
    const newBytes = B.slice(r.start, r.end + 1).toString('hex');
    console.log(`fileOff=0x${r.start.toString(16)} ${vaStr} len=${len}`);
    console.log(`  vanilla: ${oldBytes}`);
    console.log(`  d187   : ${newBytes}`);
    console.log();
}

// Stats
const totalDiffBytes = regions.reduce((s, r) => s + (r.end - r.start + 1), 0);
console.log(`Total diff bytes: ${totalDiffBytes} / ${A.length} (${(100*totalDiffBytes/A.length).toFixed(4)}%)`);
