# S2 Son Silah — Private Server

Joygame'in 2010-2015 arası Türkiye'de servis ettiği **S2: Son Silah** (LithTech FPS) için Node.js ile yazılmış server emülatörü. Oyun resmi olarak kapandığı için orijinal client'ı yerelde çalıştırabilmek amacıyla yazıldı.

> **Durum:** Login → kanal → oda → ready akışı çalışıyor. Map yükleniyor. **Ama gameplay başlamıyor** — spawn akışında çözülmemiş bir blocker var. Detay aşağıda.

---

## Hızlı bakış

| Bileşen | Port | Görev |
|---|---|---|
| `s2_auth_server` | TCP 12000 | Login, item/slot, server seçimi |
| `s2_lobby_server` | TCP 13000 | Kanal/oda/chat/hangar + dedi handshake |
| `TheRawServer.exe` | (TCP 13000'e bağlanır) | Joygame'in orijinal dedicated server'ı |
| `TheRaw.exe` / `sex.exe` | UDP 27888 | Oyun client'ı |

---

## Gerekli dosyalar

### 1. Oyun (Yandex Disk)

Tam game dosyaları (~2GB):
**https://disk.yandex.com.tr/d/E3AtjrYeUcYYgw**

İndirip masaüstünde `S2SonSilah/` adıyla aç.

### 2. `Game.Res00` ayıklama

`Game/Game.Res00` dosyası paketli geliyor, ayıklanmalı:

1. `game-binaries/ArchiveExtractor.exe` → `S2SonSilah/Game/` klasörüne kopyala.
2. `Game.Res00` dosyasını `ArchiveExtractor.exe` üzerine **sürükle-bırak**.
3. Oluşan `Game/Extracted/` klasörünün **içindeki** her şeyi kes, `Game/` köküne yapıştır.
4. Boş `Extracted/` klasörünü sil.

### 3. Patched binary'leri kopyala

| Repo'daki | Hedef |
|---|---|
| `server-binaries/Engine_Server.dll` | `S2SonSilah/Engine_Server.dll` |
| `server-binaries/TheRawServer.exe` | `S2SonSilah/TheRawServer.exe` |
| `server-binaries/StringEditRuntime.dll` | `S2SonSilah/StringEditRuntime.dll` |
| `game-binaries/GameClient.dll` | `S2SonSilah/Game/GameClient.dll` |
| `game-binaries/GameServer.dll` | `S2SonSilah/Game/GameServer.dll` |

Bunlar `GetController` popup'ını ve birkaç başka client-side check'i NOP'layan binary patch içerir.

### 4. `Game.ini` (KRİTİK)

`S2SonSilah/Game.ini` içeriği şöyle olmalı:

```ini
[Game]
ProfileName=Profile000

[HermitDediConnectIP]
IP=127.0.0.1

[DediPublicIP]
IP=127.0.0.1
```

> **Bu iki section yoksa `TheRawServer.exe` lobby'ye bağlanmaz, sessizce kapanır.**
>
> Sebep: `GameServer.dll` `CHermitNetworkMgr::Init` (`sub_100D1750`) fonksiyonu Game.ini'den `GetPrivateProfileStringA("HermitDediConnectIP", "IP", ...)` ve `GetPrivateProfileStringA("DediPublicIP", "IP", ...)` çağrılarıyla okuma yapıyor. Boşsa fallback IP garbage olduğundan TCP connect hata veriyor.

### 5. Node.js bağımlılıkları

Node.js **18+** gerekli.

```bash
cd s2_auth_server   && npm install
cd ../s2_lobby_server && npm install
```

`s2_shared/` için install gerekmez.

---

## Çalıştırma

3 ayrı terminal:

```bash
# Terminal 1
cd s2_auth_server && node index.js

# Terminal 2
cd s2_lobby_server && node index.js

# Terminal 3 (S2SonSilah klasöründe)
LaunchServer.bat
```

`LaunchServer.bat` içeriği:
```bat
@ECHO OFF
start TheRawServer.exe -userdirectory "." +errorlog 1 +alwaysflushlog 0 ^
  -gs_ip 127.0.0.1 -port 27888 -gs_Channel 1 -gs_port 13000
```

Lobby logunda doğrulama:
```
[LOBBY:CONN] >>> NEW TCP CONNECTION from 127.0.0.1:xxxxx → 127.0.0.1:13000
[LOBBY] mode = ENCRYPTED, keyByte=0xf
[LOBBY←] recv 0x410101 CN_TheRawServer_Connect (size 43)
[DEDI] handshake from 127.0.0.1, payload (27): 01000000f06c01...
[DEDI] registered ip=127.0.0.1 port=27888
```

Sonra `sex.exe` veya `TheRaw.exe`'yi başlat.

**Test hesabı:** `serefsiz` / `123` (`Game/Database/Table/Server/GM_Auth.csv`'de tanımlı).
Yeni kullanıcı: auth'a hangi user/pass girersen otomatik kayıt yapar.

---

## Mimari

```
        sex.exe / TheRaw.exe
              │
              │ TCP 12000 (login)
              ▼
        s2_auth_server  ─────────────┐
              │                       │
              │ server seç → 13000    │ session paylaşımı
              ▼                       │ (_session/users.json)
        s2_lobby_server ◄─────────────┘
              ▲
              │ TCP 13000 (control channel)
              │
        TheRawServer.exe
              │
              │ UDP 27888 (gameplay)
              ▼
        TheRaw.exe (client)
```

- **Auth**: login + envanter + server listesi gönderir, "server seç" anında client'ı disconnect eder.
- **Lobby**: kanal/oda/chat/hangar yönetir. Client `CN_StartButton` (ready) basınca dedicated'a `BaseRoomInfo + BaseUserList + BattleInfo` paketlerini yollar, sonra client'a `SN_HostConnect` ile dedi'nin UDP adresini verir.
- **TheRawServer**: ayrı bir process. Lobby'ye `CN_TheRawServer_Connect` (`0x410101`) ile el sıkışır, gameplay'de `Ready1/2/3`, `RoundStart`, `Notify` event'lerini lobby'ye iletir.

---

## Reverse Engineering Notları

### Hermit Encryption (CRC32 XOR)

```
crcTable: standart CRC32 (poly 0xEDB88320)
cipher:   byte_out[i] = keyByte XOR orig[i] XOR (crcTable[i] & 0xFF)   (i = 4..size)
crc:      CRC32 over encrypted [4..size], packet[0..3] = ~crc BE u32
header:   ENCRYPTED → BE; PLAIN → LE + sabit CRC 0x117b5a78
keyByte:  default 0x0F; per-packet rotation olabilir
```

Mode tespiti:
1. Encrypted brute-force (CRC32 validation false-positive vermez)
2. Başarısız → plain size-check (`[6..7]` LE 16..0x400 makulse)

Per-packet brute-force fallback: cached key fail olursa 0..255 tara — TheRawServer key rotation'ını bu sayede yakalıyoruz.

### Paket ID şeması

354 opcode reverse'lendi (`s2_shared/packet_ids.js`):

| Modül | Range | Örnek |
|---|---|---|
| NAccount/NIdentity | `0x1101**` | `CQ_JoyGameLogin 0x110111` |
| NLaunch/NLock | `0x2101**` | `SN_UserInfo 0x210101` |
| NMatchup/NChannel | `0x2201**` | `SN_ChannelList 0x220102` |
| NMatchup/NRoom | `0x2202**` | `CQ_Room_Create 0x220201` |
| NMatchup/NTeam | `0x2203**` | `CQ_Team_Change 0x220311` |
| NMatchup/NPlay | `0x2221**` | `BaseRoomInfo 0x222111`, `BattleInfo 0x222114` |
| NHosting/NGuest | `0x4203**` | `HostConnect 0x420303`, `BattleStart 0x420310` |
| NHangar | `0x2401**`, `0x2402**` | 12 paket |
| TheRawServer ↔ Lobby | `0x4101**`, `0x4202**` | `Connect 0x410101`, `Ready1/2/3 0x420203/04/06` |
| Engine sistem | `0x20080-86` | `Heartbeat`, `KeepAlive`, `KeepAlive2` |

### LithTech Engine MID'leri (UDP gameplay)

`GameServer.dll sub_100273E0` reverse'inden:

| MID | İsim | Amaç |
|---|---|---|
| 96 | `PLAYER_SPECTATORMODE` | Spectator toggle |
| **103** | **`PLAYER_STATE_CHANGE`** | **1=Alive, 5=Spectator** — spawn kilidi burada |
| 104 | `PLAYER_RESPAWN` | dedi → client "respawn'a izinlisin" |
| 105 | `CN_PlayerRespawn` | client → dedi "respawn istiyorum" |
| 117 | `PLAYER_DAMAGE` | |
| **121** | **`PLAYER_TELEPORT`** | spawn pozisyonu |
| 153 | `SQUAD_INFO` | |
| 175 | `TEAMEVENT` | |
| 196 | `SERVERGAMESTATE` | dedi → client state machine güncellemesi |
| 230 | `SFX_MESSAGE` | |
| 240 | `DEDI_REGISTER` | |

### Dedi state machine (`sub_100CD580`)

```
1 = Loading       → InWorld_OnMessage tetiklerse → 2
2 = Hosting       → all-clients-loaded → Ready2 + → 3
3 = Countdown     → countdown bitince RoundStart + → 4
4 = Playing       → [+201]==1 + timer → sub_100CC180 (gerçek spawn)
5 = GameOver      → "Kazanma" ekranı tetiklenir
6 = ?
7 = Cleanup       → 1
```

`[+201]` flag'i set edilmediği için state 4'te spawn olmuyor — bu blocker'ın kökü.

### `OnAddClient() 2` BAN

`GameServer.dll sub_10085CF0` (`ServerConnectionMgr::OnAddClient`) → `0x10085DEB`:

```c
if ( *(this + 9) != v19 || *(BYTE *)(sub_1002D040() + 108) ) {
    // OK path
} else {
    BAN("ServerConnectionMgr::OnAddClient() 2");
}
```

BAN olur eğer:
- `v19 == END` (client'ın userId expected list'TE YOK), VE
- `manager_mode == 0` (Game.ini'de `[ServerDevMode] Mode=1` yok)

Önlem: Lobby `CN_StartButton` aldığında dedi'ye **`BattleInfo + ChangeRound (0x222122) + 0x222213 + 0x222121`** paketleri gönderir. Bu set user'ı dedi'nin expected list'ine ekler. Aynı set ne yazık ki round-end'i de tetikliyor — izole edilemedi.

### `CN_TheRawServer_Connect` handshake (`0x410101`)

`GameServer.dll sub_100D16C0` builder, 43 byte:

```
payload[0..3]   DWORD  flag = 1
payload[4..5]   WORD   port (default 27888)
payload[6]      BYTE   subFlag
payload[7..21]  CHAR   IP string (15 byte max)
payload[22]     0      terminator
payload[23..26] DWORD  serverId
```

---

## Mevcut Durum

### Çalışan
- Auth login (PLAIN + ENCRYPTED, per-packet key rotation)
- Server seçimi → lobby geçişi
- Kanal seç + oda oluştur/gir/çık + chat
- Hangar (12 envanter paketi reverse'li, `inventory.json` persistence)
- Map seçimi (152 map `Map.csv`'den)
- Ready → BattleStart → map loading başlar
- TheRawServer ↔ Lobby control channel handshake
- Admin panel (`/CmdTcpFn login serefsiz 123` → GM_Auth check)
- Runtime map değiştirme (lobby terminal'inde `next/prev/map <id>/good/bad`)

### Çalışmayan (BLOCKER)
- **Spawn**: Client `eClientConnectionState_InWorld`'a ulaşıyor, `CCharacterFX::Init()` çalışıyor (karakter create), AMA:
  - `PlayerState=5` (Spectator) loop'unda kalıyor → loading ekranı kapanmaz
  - VEYA map loading sonrası direkt "Kazanma" ekranı (round 0/0)

### Yarım kalan
- Kill/score/spawn relay handler'ları (gameplay başlamadığı için yazılmadı)
- Friend / Mail / Tournament / Guild / Marble (ack stub'ları var)
- Encrypted client (TheRaw.exe) lobby geçişi (auth OK, lobby loop)

---

## Bilinen sorunlar

| Sorun | Sebep | Çözüm |
|---|---|---|
| Map loading'de takılı, `PlayerState=5` loop | Dedi `SetPlayerState(5)` çağırıyor, çıkış trigger'ı bilinmiyor | — |
| Map loading sonrası anında "Kazanma" | Spawn paketleri round-end'i de tetikliyor | — |
| `OnAddClient() 2` BAN | Expected list eksik | `BattleInfo + ChangeRound + 0x222213 + 0x222121` zorunlu |
| `TheRawServer.exe` başlamıyor | `Game.ini`'de `[HermitDediConnectIP]` yok | Yukarıdaki konfigi ekle |
| Resource yüklenmiyor | `Game.Res00` ayıklanmamış | `ArchiveExtractor.exe` ile ayıkla |

---

## Lisans

LICENSE dosyasına bakın.
