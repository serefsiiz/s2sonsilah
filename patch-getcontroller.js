'use strict';

// ==========================================================================
// GameClient.dll — GetController popup binary patch
//
// CMissionMgr::GetController() (sub_10087A20) lookup başarısız olduğunda
// MessageBoxA modal popup atıyor → maça girişi engelliyor.
// Bu script popup tetikleyen 20 byte'ı NOP'lar; fonksiyon "xor eax, eax;
// pop ecx; retn 4" ile düzgün çıkar (eski caller'lar 0 dönüş bekliyor zaten).
//
// Patch noktası (memory):  0x10087A47 — 0x10087A5A (20 byte)
// Eski:  6A 00 68 7C 62 49 10 68 30 62 49 10 6A 00 FF 15 00 25 48 10
//        push 0; push offset Caption; push offset Text; push 0;
//        call ds:__imp_MessageBoxA
// Yeni:  90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  (NOP × 20)
//
// Kullanım:
//   node patch-getcontroller.js                      → varsayılan path
//   node patch-getcontroller.js path\to\GameClient.dll
//   node patch-getcontroller.js path\to\GameClient.dll --revert
// ==========================================================================

const fs   = require('fs');
const path = require('path');

const DEFAULT_DLL = 'C:\\Users\\Akıncı\\Desktop\\S2SonSilah\\Game\\GameClient.dll';

const ORIG_BYTES = Buffer.from([
    0x6A, 0x00,                                     // push 0          (uType)
    0x68, 0x7C, 0x62, 0x49, 0x10,                   // push 0x1049627C (lpCaption)
    0x68, 0x30, 0x62, 0x49, 0x10,                   // push 0x10496230 (lpText)
    0x6A, 0x00,                                     // push 0          (hWnd)
    0xFF, 0x15, 0x00, 0x25, 0x48, 0x10,             // call ds:[0x10482500]  (MessageBoxA)
]);

const PATCHED_BYTES = Buffer.alloc(ORIG_BYTES.length, 0x90);   // 20 × NOP

function findUniqueOffset(buf, pattern) {
    let foundAt = -1;
    let count = 0;
    for (let i = 0; i + pattern.length <= buf.length; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
            if (buf[i + j] !== pattern[j]) { match = false; break; }
        }
        if (match) {
            count++;
            foundAt = i;
            if (count > 1) break;
        }
    }
    return { offset: foundAt, count };
}

function main() {
    const args = process.argv.slice(2);
    const revert = args.includes('--revert');
    const dllPath = args.find(a => !a.startsWith('--')) || DEFAULT_DLL;

    if (!fs.existsSync(dllPath)) {
        console.error(`[patch] dosya yok: ${dllPath}`);
        process.exit(1);
    }

    console.log(`[patch] target: ${dllPath}`);
    console.log(`[patch] mode  : ${revert ? 'REVERT (NOP→original)' : 'PATCH (original→NOP)'}`);

    const buf  = fs.readFileSync(dllPath);
    const find = revert ? PATCHED_BYTES : ORIG_BYTES;
    const set  = revert ? ORIG_BYTES   : PATCHED_BYTES;

    const { offset, count } = findUniqueOffset(buf, find);
    if (count === 0) {
        if (revert) {
            console.error(`[patch] NOP pattern bulunamadı — dosya zaten orijinal mi?`);
        } else {
            // Belki zaten patched — kontrol et
            const { count: patchedCount } = findUniqueOffset(buf, PATCHED_BYTES);
            if (patchedCount > 0) {
                console.log(`[patch] dosya zaten YAMALI (${patchedCount} NOP pattern bulundu).`);
                console.log(`[patch] geri almak için: node patch-getcontroller.js --revert`);
                process.exit(0);
            }
            console.error(`[patch] orijinal byte pattern bulunamadı — DLL versiyonu farklı olabilir.`);
        }
        process.exit(1);
    }
    if (count > 1) {
        console.error(`[patch] pattern ${count} kere bulundu (tek olması lazımdı) — risk var, abort.`);
        process.exit(1);
    }

    console.log(`[patch] hedef offset (file): 0x${offset.toString(16).toUpperCase()}`);

    // Backup (sadece patch modunda)
    if (!revert) {
        const bak = dllPath + '.bak';
        if (!fs.existsSync(bak)) {
            fs.writeFileSync(bak, buf);
            console.log(`[patch] backup oluşturuldu: ${bak}`);
        } else {
            console.log(`[patch] backup zaten mevcut, atlanıyor: ${bak}`);
        }
    }

    // Yaz
    set.copy(buf, offset);
    fs.writeFileSync(dllPath, buf);

    // Verify
    const re = fs.readFileSync(dllPath);
    let ok = true;
    for (let i = 0; i < set.length; i++) {
        if (re[offset + i] !== set[i]) { ok = false; break; }
    }
    if (!ok) {
        console.error(`[patch] verify FAIL — yazılamadı?`);
        process.exit(1);
    }

    console.log(`[patch] ✓ başarılı. ${set.length} byte değiştirildi.`);
    if (!revert) {
        console.log(`[patch] Şimdi GameClient.dll yüklü oyunda GetController popup'ı atlanacak.`);
        console.log(`[patch] Geri almak için:  node ${path.basename(__filename)} "${dllPath}" --revert`);
        console.log(`[patch] Backup'tan da restore edebilirsin: copy "${dllPath}.bak" "${dllPath}"`);
    }
}

main();
