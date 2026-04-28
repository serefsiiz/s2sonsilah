'use strict';

// ==========================================================================
// S2: Persistent storage — accounts + inventory
//
// JSON tabanlı (DB yok, kullanıcı tercihi). Atomic write (tmp + rename).
//
// Dosyalar (proje root'unun bir üstü = ../_session/):
//   accounts.json   — username → { passwordHash, salt, userId, registeredAt }
//   inventory.json  — username → { items, slots, money }
//   users.json      — IP → { username, userId } (mevcut auth↔lobby session paylaşımı)
//
// Şifre hashing: salt (16 byte random hex) + sha256(salt + password) — bcrypt yok
// (saf Node built-in `crypto`, ekstra dependency istemedik).
// ==========================================================================

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// --------------------------------------------------------------------------
// PATHS
// --------------------------------------------------------------------------

const SESSION_DIR    = path.resolve(__dirname, '..', '_session');
const ACCOUNTS_FILE  = path.join(SESSION_DIR, 'accounts.json');
const INVENTORY_FILE = path.join(SESSION_DIR, 'inventory.json');
const USERS_FILE     = path.join(SESSION_DIR, 'users.json');

function ensureDir() {
    if (!fs.existsSync(SESSION_DIR)) fs.mkdirSync(SESSION_DIR, { recursive: true });
}

function readJson(file, fallback) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (_) {
        return fallback;
    }
}

function writeJsonAtomic(file, data) {
    ensureDir();
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, file);
}

// --------------------------------------------------------------------------
// ACCOUNTS
// --------------------------------------------------------------------------

function hashPassword(password, salt) {
    return crypto.createHash('sha256').update(salt + password).digest('hex');
}

function readAccounts() {
    return readJson(ACCOUNTS_FILE, {});
}

function writeAccounts(accounts) {
    writeJsonAtomic(ACCOUNTS_FILE, accounts);
}

// Username için sabit userId üretir (hash bazlı, deterministic).
function userIdFromUsername(username) {
    const h = crypto.createHash('sha256').update(username).digest();
    return (h.readUInt32BE(0) % 1_000_000) + 1;
}

// Yeni hesap için default stats — Bilgilerim/Records ekranı bunlardan dolar.
function defaultStats() {
    return {
        // Records (SN_Record)
        kills        : 0,
        deaths       : 0,
        assists      : 0,
        wins         : 0,
        losses       : 0,
        draws        : 0,
        playTimeSec  : 0,
        exp          : 0,
        level        : 1,
        rankPoints   : 0,
        // Cumulative stats
        headshots    : 0,
        shotsFired   : 0,
        shotsHit     : 0,
        // Match counts
        totalMatches : 0,
    };
}

function defaultClan() {
    return {
        id       : 0,
        name     : '',
        mark     : 0,
        rank     : 0,   // 0=member, 1=officer, 2=master
        joinedAt : 0,
    };
}

// Kayıtlı değilse yeni hesap aç. Kayıtlıysa şifreyi doğrula.
// Dönüş: { ok: bool, isNew: bool, userId, reason }
function loginOrRegister(username, password) {
    if (!username) return { ok: false, reason: 'empty username' };
    const accounts = readAccounts();

    if (accounts[username]) {
        // Mevcut hesap → şifre kontrol
        const a = accounts[username];
        const candHash = hashPassword(password || '', a.salt);
        if (candHash !== a.passwordHash) {
            return { ok: false, reason: 'wrong password', userId: a.userId };
        }
        // Eski hesap → eksik alanları doldur (stats/clan migration)
        let migrated = false;
        if (!a.stats) { a.stats = defaultStats(); migrated = true; }
        if (!a.clan)  { a.clan  = defaultClan();  migrated = true; }
        if (migrated) writeAccounts(accounts);
        return { ok: true, isNew: false, userId: a.userId };
    }

    // Yeni hesap → otomatik kayıt
    const salt    = crypto.randomBytes(16).toString('hex');
    const newAcc  = {
        passwordHash : hashPassword(password || '', salt),
        salt,
        userId       : userIdFromUsername(username),
        registeredAt : new Date().toISOString(),
        stats        : defaultStats(),
        clan         : defaultClan(),
    };
    accounts[username] = newAcc;
    writeAccounts(accounts);
    return { ok: true, isNew: true, userId: newAcc.userId };
}

// --------------------------------------------------------------------------
// STATS / CLAN getters & setters (operate on accounts.json)
// --------------------------------------------------------------------------

function getAccount(username) {
    const accounts = readAccounts();
    const a = accounts[username];
    if (!a) return null;
    if (!a.stats) a.stats = defaultStats();
    if (!a.clan)  a.clan  = defaultClan();
    return a;
}

function getStats(username) {
    const a = getAccount(username);
    return a ? a.stats : defaultStats();
}

// deltaObj: { kills: +1, deaths: +1, exp: +50, ... } → toplama uygulanır.
function updateStats(username, deltaObj) {
    const accounts = readAccounts();
    if (!accounts[username]) return;
    if (!accounts[username].stats) accounts[username].stats = defaultStats();
    const s = accounts[username].stats;
    for (const k of Object.keys(deltaObj || {})) {
        s[k] = (s[k] || 0) + (deltaObj[k] || 0);
    }
    writeAccounts(accounts);
}

function getClan(username) {
    const a = getAccount(username);
    return a ? a.clan : defaultClan();
}

function setClan(username, clanData) {
    const accounts = readAccounts();
    if (!accounts[username]) return;
    accounts[username].clan = Object.assign(defaultClan(), clanData || {});
    writeAccounts(accounts);
}

// --------------------------------------------------------------------------
// MONEY (lives in inventory.json — gold/cash deduction & top-up)
// --------------------------------------------------------------------------

function getMoney(username) {
    const inv = getOrCreateInventory(username);
    return Object.assign({ gold: 0, cash: 0 }, inv.money || {});
}

// amount > 0 düşürür, < 0 ekler. Yetersiz bakiye → false.
function chargeGold(username, amount) {
    const inv = getOrCreateInventory(username);
    if (!inv.money) inv.money = { gold: 0, cash: 0 };
    if (amount > 0 && inv.money.gold < amount) return false;
    inv.money.gold -= amount;
    saveInventory(username, inv);
    return true;
}

function chargeCash(username, amount) {
    const inv = getOrCreateInventory(username);
    if (!inv.money) inv.money = { gold: 0, cash: 0 };
    if (amount > 0 && inv.money.cash < amount) return false;
    inv.money.cash -= amount;
    saveInventory(username, inv);
    return true;
}

function addMoney(username, gold, cash) {
    const inv = getOrCreateInventory(username);
    if (!inv.money) inv.money = { gold: 0, cash: 0 };
    inv.money.gold += (gold || 0);
    inv.money.cash += (cash || 0);
    saveInventory(username, inv);
    return inv.money;
}

// --------------------------------------------------------------------------
// INVENTORY
// --------------------------------------------------------------------------

// Yeni hesaplara verilen default envanter.
// DefaultItem.csv'deki ID'ler (group ID'leri); client bunları kendi item table'ında
// "%d%02d" + lookup ile gerçek 9-digit varyantlara çeviriyor (sub_100312B0 reverse).
function defaultInventory() {
    return {
        items: [
            // { id: itemGroupId, qty, active (= equipped/in-use), expiry (epoch sec, 0=permanent) }
            { id: 2111099, qty: 1, active: 1, expiry: 0 },   // karakter (Igor / default)
            { id: 2113099, qty: 1, active: 1, expiry: 0 },   // karakter alt
            { id: 1110099, qty: 1, active: 1, expiry: 0 },   // primary (XM177-EX)
            { id: 1140099, qty: 1, active: 1, expiry: 0 },   // primary alt
            { id: 1210099, qty: 1, active: 1, expiry: 0 },   // secondary (pistol)
            { id: 1310099, qty: 1, active: 1, expiry: 0 },   // melee (knife)
            { id: 1410099, qty: 1, active: 1, expiry: 0 },   // grenade
        ],
        slots: {
            // Aktif loadout — SN_SlotInfo ile gönderilir
            character    : 2111099,
            primary      : 1110099,
            secondary    : 1210099,
            melee        : 1310099,
            grenade      : 1410099,
            costumeHead  : 0,
            costumeBody  : 0,
            costumeBack  : 0,
            costumeExtra1: 0,
            costumeExtra2: 0,
            costumeExtra3: 0,
        },
        money: {
            gold: 999999,
            cash: 999999,
        },
    };
}

function readInventory() {
    return readJson(INVENTORY_FILE, {});
}

function writeInventory(inventory) {
    writeJsonAtomic(INVENTORY_FILE, inventory);
}

// Kullanıcının envanterini getir; yoksa default ile yarat ve kaydet.
function getOrCreateInventory(username) {
    const inv = readInventory();
    if (!inv[username]) {
        inv[username] = defaultInventory();
        writeInventory(inv);
    }
    return inv[username];
}

// Kullanıcının envanterini disk'e yaz.
function saveInventory(username, userInventory) {
    const inv = readInventory();
    inv[username] = userInventory;
    writeInventory(inv);
}

// --------------------------------------------------------------------------
// IP-BASED SESSION (auth → lobby köprüsü, mevcut davranış)
// --------------------------------------------------------------------------

function readUsersSession() {
    return readJson(USERS_FILE, {});
}

function writeUsersSession(remoteAddress, username, userId) {
    const ip = (remoteAddress || '').replace(/^::ffff:/, '');
    const map = readUsersSession();
    map[ip] = { username, userId, ts: Date.now() };
    writeJsonAtomic(USERS_FILE, map);
}

function lookupUserByIp(remoteAddress) {
    const ip = (remoteAddress || '').replace(/^::ffff:/, '');
    const map = readUsersSession();
    return map[ip] || null;
}

// --------------------------------------------------------------------------
// EXPORTS
// --------------------------------------------------------------------------

module.exports = {
    // accounts
    loginOrRegister,
    userIdFromUsername,
    getAccount,
    // stats
    defaultStats,
    getStats,
    updateStats,
    // clan
    defaultClan,
    getClan,
    setClan,
    // inventory
    defaultInventory,
    getOrCreateInventory,
    saveInventory,
    // money
    getMoney,
    chargeGold,
    chargeCash,
    addMoney,
    // session bridge
    writeUsersSession,
    lookupUserByIp,
    // paths (debug)
    SESSION_DIR, ACCOUNTS_FILE, INVENTORY_FILE, USERS_FILE,
};
