'use strict';

// ==========================================================================
// GameServer.dll — OnAddClient BAN bypass binary patch
//
// CHermitProcessMsg / ServerConnectionMgr::OnAddClient (sub_10085CF0) içinde
// dedi client bağlandığında "expected user list" lookup yapıyor. Eğer client'ın
// userId'si listede yoksa BAN ediyor:
//   "ServerConnectionMgr::OnAddClient() 2"
//   eClientConnectionError_Ban
//
// Patch noktası (memory):  0x10085DEB
// İlgili kod akışı:
//   0x10085de4: 8B 45 24            mov eax, [ebp+24h]            ; this->expected_list_end
//   0x10085de7: 3B 44 24 18         cmp eax, [esp+18h]            ; cmp END, lookup_result
//   0x10085deb: 75 1F               jnz short loc_10085E0C        ; if !=, OK path
//   0x10085ded: E8 ...              call sub_1002D040             ; get singleton
//   0x10085df2: 80 78 6C 00         cmp byte ptr [eax+6Ch], 0     ; manager_mode check
//   0x10085df6: 75 14               jnz short loc_10085E0C        ; if != 0, OK path
//   0x10085df8: 68 ... "OnAddClient() 2"                          ; BAN message
//
// Patch: 0x10085DEB byte 0x75 (jnz) → 0xEB (jmp). Yani lookup sonucu ne olursa
// olsun ALWAYS jump to OK path. BAN ASLA çalışmaz.
//
// Bu tek-byte patch sayesinde lobby'nin BaseUserList format'ı yanlış olsa bile
// client connect edebilir. Asıl BaseUserList format düzeltilince geri alınabilir.
//
// Kullanım:
//   node patch-onaddclient-ban.js                 → varsayılan path
//   node patch-onaddclient-ban.js path\to\GameServer.dll
//   node patch-onaddclient-ban.js path\to\GameServer.dll --revert
// ==========================================================================

const fs   = require('fs');
const path = require('path');

const DEFAULT_DLL = 'C:\\Users\\Akıncı\\Desktop\\S2SonSilah\\Game\\GameServer.dll';

// Pattern: 8 byte context BEFORE patch + the 0x75 byte that changes + tail context.
// Tek pattern bulunsun diye yeterince uzun.
const ORIG_BYTES = Buffer.from([
    0x8B, 0x45, 0x24,                              // mov eax, [ebp+24h]
    0x3B, 0x44, 0x24, 0x18,                        // cmp eax, [esp+18h]
    0x75, 0x1F,                                    // jnz short loc_10085E0C       ← PATCH HERE (0x75 → 0xEB)
    0xE8, 0x4E, 0x72, 0xFA, 0xFF,                  // call sub_1002D040
    0x80, 0x78, 0x6C, 0x00,                        // cmp byte ptr [eax+6Ch], 0
    0x75, 0x14,                                    // jnz short loc_10085E0C
]);

const PATCHED_BYTES = Buffer.from(ORIG_BYTES);
PATCHED_BYTES[7] = 0xEB;                            // jnz → jmp

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
    console.log(`[patch] mode  : ${revert ? 'REVERT (jmp→jnz)' : 'PATCH (jnz→jmp, BAN bypass)'}`);

    const buf  = fs.readFileSync(dllPath);
    const find = revert ? PATCHED_BYTES : ORIG_BYTES;
    const set  = revert ? ORIG_BYTES   : PATCHED_BYTES;

    const { offset, count } = findUniqueOffset(buf, find);
    if (count === 0) {
        if (revert) {
            console.error(`[patch] PATCHED pattern bulunamadı — dosya zaten orijinal mi?`);
        } else {
            const { count: patchedCount } = findUniqueOffset(buf, PATCHED_BYTES);
            if (patchedCount > 0) {
                console.log(`[patch] dosya zaten YAMALI (${patchedCount} match).`);
                console.log(`[patch] geri almak için: node patch-onaddclient-ban.js --revert`);
                process.exit(0);
            }
            console.error(`[patch] orijinal pattern bulunamadı — DLL versiyonu farklı olabilir.`);
        }
        process.exit(1);
    }
    if (count > 1) {
        console.error(`[patch] pattern ${count} kere bulundu — risk var, abort.`);
        process.exit(1);
    }

    console.log(`[patch] hedef offset (file): 0x${offset.toString(16).toUpperCase()}`);

    if (!revert) {
        const bak = dllPath + '.bak';
        if (!fs.existsSync(bak)) {
            fs.writeFileSync(bak, buf);
            console.log(`[patch] backup oluşturuldu: ${bak}`);
        } else {
            console.log(`[patch] backup zaten mevcut, atlanıyor: ${bak}`);
        }
    }

    set.copy(buf, offset);
    fs.writeFileSync(dllPath, buf);

    const re = fs.readFileSync(dllPath);
    let ok = true;
    for (let i = 0; i < set.length; i++) {
        if (re[offset + i] !== set[i]) { ok = false; break; }
    }
    if (!ok) {
        console.error(`[patch] verify FAIL — yazılamadı?`);
        process.exit(1);
    }

    console.log(`[patch] ✓ başarılı. ${set.length} byte pattern, sadece 1 byte değişti (offset+7: 0x75 → 0xEB).`);
    if (!revert) {
        console.log(`[patch] OnAddClient() 2 BAN check artık her zaman bypass edilecek.`);
        console.log(`[patch] Geri almak için:  node ${path.basename(__filename)} --revert`);
        console.log(`[patch] Backup'tan da restore edebilirsin: copy "${dllPath}.bak" "${dllPath}"`);
    }
}

main();
