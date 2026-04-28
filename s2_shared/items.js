'use strict';

// ==========================================================================
// S2: Item registry — TotalItem.csv + Shop.csv loader
//
// Client'in kullandığı tabloları (Database\Table\) okuyup item template +
// shop fiyat veritabanı oluşturur. Lobby Buy/CashBuy bu tablodan gerçek
// fiyat ve süreyi alır.
//
// Tablolar:
//   TotalItem.csv  — itemId → name, type, duration (Limite, dakika), category
//   Shop.csv       — itemId → price, isCash
// ==========================================================================

const fs   = require('fs');
const path = require('path');

const GAME_TABLE_DIR = 'C:\\Users\\Akıncı\\Desktop\\S2SonSilah\\Game\\Database\\Table';

// item kategorileri (TotalItem.csv ItemType + MediumGroup):
//   ItemType 1 = silah  (Medium 1=primary, 2=primary alt?, 3=secondary, 4=melee?, 5=grenade)
//   ItemType 2 = karakter / costume (kıyafet)
//   ItemType 3 = consumable
//   ItemType 4 = function / utility
//
// SlotInfo'da slot index'leri (sub_100312B0 reverse'inden):
//   0 = character body
//   1 = primary weapon
//   2 = secondary weapon
//   3 = melee
//   4 = grenade
//   5..10 = costume slots (head, body, etc.)

let _items = null;   // itemId -> { id, name, type, mediumGroup, lowGroup, isPeriod, durationMin, group }
let _shop  = null;   // itemId -> { price, isCash, label, menuNum }
let _maps  = null;   // mapIndex -> { index, name, mode, ruleIndex, settingIndex, isFixWeapon, priorityWeaponMode, isRoleChange }
let _gmAuth = null;  // [{ index, ip, id, password }]  — admin whitelist (Server/GM_Auth.csv)

// Naive CSV parser: comma-separated, no quoting (yetiyor — tablolarda quote yok)
function parseCsv(file) {
    const text = fs.readFileSync(file, 'latin1');   // CSV'lerde non-UTF8 (Korece artıkları) var
    const lines = text.split(/\r?\n/).filter(l => l.length);
    const headers = lines.shift().split(',').map(s => s.trim());
    const rows = [];
    for (const line of lines) {
        const cells = line.split(',');
        const row = {};
        for (let i = 0; i < headers.length; i++) row[headers[i]] = (cells[i] || '').trim();
        rows.push(row);
    }
    return rows;
}

function loadItems() {
    if (_items) return _items;
    _items = new Map();
    try {
        const rows = parseCsv(path.join(GAME_TABLE_DIR, 'TotalItem.csv'));
        for (const r of rows) {
            const id = parseInt(r.ItemIndex, 10);
            if (!id) continue;
            _items.set(id, {
                id,
                name        : r.Name,
                type        : parseInt(r.ItemType,    10) || 0,
                mediumGroup : parseInt(r.MediumGroup, 10) || 0,
                lowGroup    : parseInt(r.LowGroup,    10) || 0,
                group       : parseInt(r.ItemGroup,   10) || 0,
                isPeriod    : parseInt(r.IsPeriod,    10) === 1,
                durationMin : parseInt(r.Limite,      10) || 0,
                canDelete   : parseInt(r.CanDelete,   10) === 1,
                uiCategory  : parseInt(r.UI_Category, 10) || 0,
            });
        }
        console.log(`[items] loaded ${_items.size} items from TotalItem.csv`);
    } catch (err) {
        console.warn(`[items] TotalItem.csv yüklenemedi: ${err.message}`);
    }
    return _items;
}

function loadMaps() {
    if (_maps) return _maps;
    _maps = new Map();
    try {
        const rows = parseCsv(path.join(GAME_TABLE_DIR, 'Map.csv'));
        for (const r of rows) {
            const idx = parseInt(r.INDEX, 10);
            if (!idx) continue;
            _maps.set(idx, {
                index              : idx,
                name               : r.MapName,
                mode               : r.ModeName,                              // "Bomb", "DeathMatch", "SuddenDeath" vb.
                ruleIndex          : parseInt(r.RuleIndex,         10) || 0,
                settingIndex       : parseInt(r.SettingIndex,      10) || 0,
                clanSetting        : parseInt(r.Clan_SettingIndex, 10) || 0,
                gambleSetting      : parseInt(r.Gamble_SettingIndex,10) || 0,
                isFixWeapon        : parseInt(r.IsFixWeapon,       10) || 0,
                priorityWeaponMode : parseInt(r.PriorityWeaponMode,10) || 0,
                isRoleChange       : parseInt(r.IsRoleChange,      10) || 0,
            });
        }
        console.log(`[items] loaded ${_maps.size} maps from Map.csv`);
    } catch (err) {
        console.warn(`[items] Map.csv yüklenemedi: ${err.message}`);
    }
    return _maps;
}

function loadGmAuth() {
    if (_gmAuth) return _gmAuth;
    _gmAuth = [];
    try {
        const rows = parseCsv(path.join(GAME_TABLE_DIR, 'Server', 'GM_Auth.csv'));
        for (const r of rows) {
            const idx = parseInt(r.Index, 10);
            if (!idx) continue;
            _gmAuth.push({
                index    : idx,
                ip       : (r.IP       || '').trim(),
                id       : (r.ID       || '').trim(),
                password : (r.Password || '').trim(),
            });
        }
        console.log(`[items] loaded ${_gmAuth.length} GM auth entries from Server/GM_Auth.csv`);
    } catch (err) {
        console.warn(`[items] GM_Auth.csv yüklenemedi: ${err.message}`);
    }
    return _gmAuth;
}

// Adminlik kontrolü: (IP, username, password) GM_Auth.csv'de var mı?
// IP wildcard değil — birebir match. Boş username/password reddedilir.
function checkGmAuth(remoteIp, username, password) {
    if (!username || !password) return false;
    const ip = (remoteIp || '').replace(/^::ffff:/, '').trim();
    for (const a of loadGmAuth()) {
        if (a.ip === ip && a.id === username && a.password === password) return true;
    }
    return false;
}

function loadShop() {
    if (_shop) return _shop;
    _shop = new Map();
    try {
        const rows = parseCsv(path.join(GAME_TABLE_DIR, 'Shop.csv'));
        for (const r of rows) {
            const id = parseInt(r.ShopIndex, 10);
            if (!id) continue;
            _shop.set(id, {
                price   : parseInt(r.Price,   10) || 0,
                isCash  : parseInt(r.IsCash,  10) === 1,
                isShow  : parseInt(r.IsShow,  10) === 1,
                label   : parseInt(r.Label,   10) || 0,
                menuNum : parseInt(r.MenuNum, 10) || 0,
            });
        }
        console.log(`[items] loaded ${_shop.size} shop entries from Shop.csv`);
    } catch (err) {
        console.warn(`[items] Shop.csv yüklenemedi: ${err.message}`);
    }
    return _shop;
}

// Public API ---------------------------------------------------------------

function getItem(itemId) {
    return loadItems().get(Number(itemId)) || null;
}

function getShopEntry(itemId) {
    return loadShop().get(Number(itemId)) || null;
}

// Item süresi (saniye). 0 → permanent. Period değilse 0.
function getItemDurationSec(itemId) {
    const it = getItem(itemId);
    if (!it || !it.isPeriod || !it.durationMin) return 0;
    if (it.durationMin >= 99999999) return 0;   // "unlimited" → permanent
    return it.durationMin * 60;
}

// Slot mapping — ItemType + MediumGroup'a göre hangi inventory.slots key'ine atanır.
//   weapon medium 1 → primary
//   weapon medium 2 → secondary
//   weapon medium 3 → melee
//   weapon medium 4 → grenade
//   weapon medium 5 → primary alt (?)
//   character/costume → character / costume slots
function getSlotKey(itemId) {
    const it = getItem(itemId);
    if (!it) return null;
    if (it.type === 1) {
        // Silah — medium ile alt türü belirle
        switch (it.mediumGroup) {
            case 1: return 'primary';     // rifle / sniper
            case 2: return 'secondary';   // pistol
            case 3: return 'melee';       // knife
            case 4: return 'grenade';     // grenade
            default: return 'primary';
        }
    }
    if (it.type === 2) {
        // Karakter / costume
        if (it.mediumGroup === 1) return 'character';   // ana karakter modeli
        if (it.mediumGroup === 2) return 'costumeHead';
        if (it.mediumGroup === 3) return 'costumeBody';
        if (it.mediumGroup === 4) return 'costumeBack';
        return 'character';
    }
    return null;   // consumable / utility — slot'a koyulmaz
}

function getMap(mapIdx) {
    return loadMaps().get(Number(mapIdx)) || null;
}

// Map.csv RuleIndex → CMissionMgr mission type (sub_10086FC0 OnEnterWorld switch)
// Reverse'lenmiş mission constructor'ları:
//   case  1 → CMission DeathMatch
//   case  3 → CMission Bomb (sub_1008AD70)
//   case  5 → CMission Capture (sub_1008AC50)
//   case  7 → CMission Rescue (sub_1008AD10)
//   case  9 → CMissionCaptin (Captain mode, sub_100851D0)
//   case 10 → ?
//   default → base CMission (sub_1008A730)
//
// Map.csv RuleIndex değerleri:
//   3002 = Bomb       → mission type 3
//   3006 = DeathMatch → mission type 1
//   3007 = SuddenDeath→ mission type 1 (DeathMatch tabanlı)
//   3003 = Rescue     → mission type 7
//   3008 = Captain    → mission type 9
function getMissionTypeForRule(ruleIndex) {
    switch (Number(ruleIndex)) {
        case 3002: return 3;   // Bomb
        case 3003: return 7;   // Rescue
        case 3006: return 1;   // DeathMatch
        case 3007: return 1;   // SuddenDeath
        case 3008: return 9;   // Captain
        default:   return 1;   // Bilinmeyen → DeathMatch fallback
    }
}

// Vehicle/RescueArea entity'si OLMAYAN basit DeathMatch map'leri (CMissionMgr
// GetController(6/4) popup'ı atmasın). Bilinen güvenli liste.
const SAFE_DEATHMATCH_MAPS = [10004, 10006, 10010, 10012, 10014, 10027, 10031];

function getDefaultSafeMapId() {
    // Test için ENV override: S2_DEFAULT_MAP=10018 node ...
    if (process.env.S2_DEFAULT_MAP) {
        const id = parseInt(process.env.S2_DEFAULT_MAP, 10);
        if (id) return id;
    }
    return 10006;   // HeadHunting — clean DeathMatch
}

// Selected mapId'i slot 0'a koyup, SAFE DeathMatch map'leriyle 5 ek slot doldur.
// SN_Room_Info'nun MAP_SLOTS array'i için 6 entry sınırı var (sub_1006FB20 reverse).
// Default popüler liste: vehicle/mission entity içermeyen DeathMatch map'leri
// (GetController popup'ı atmamak için).
function buildMapSlots(selectedMapId, popularIds = SAFE_DEATHMATCH_MAPS) {
    const all = loadMaps();
    const out = [];
    const used = new Set();
    const sel = all.get(Number(selectedMapId));
    if (sel) { out.push(sel); used.add(sel.index); }
    for (const id of popularIds) {
        if (out.length >= 6) break;
        if (used.has(id)) continue;
        const m = all.get(id);
        if (m) { out.push(m); used.add(id); }
    }
    return out;
}

module.exports = {
    getItem,
    getShopEntry,
    getItemDurationSec,
    getSlotKey,
    getMap,
    buildMapSlots,
    getMissionTypeForRule,
    getDefaultSafeMapId,
    SAFE_DEATHMATCH_MAPS,
    loadItems,
    loadShop,
    loadMaps,
    loadGmAuth,
    checkGmAuth,
};
