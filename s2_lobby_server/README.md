# S2 Lobby Server

Port: **13000**

## Çalıştır
```
cd s2_lobby_server
npm install
npm start
```

## Sorumluluk
- `CQ_Join` → lobby giriş + envanter bundle (`SN_ItemList`, `SN_SlotInfo`, `SN_LockEnd`)
- `CQ_EnterUser_Channel` → kanal giriş, `SN_UserList_Channel` broadcast
- Hangar / Equipment paketleri (Open, ChangePart, Use, Delete, Active, CashBuy)
- Room: Create, Enter, Leave, ChangeMapInfo, ChangeName, ChangeOption, ChangeBoundary
- Team: Change, ExchangeTeam, ChangeLeader
- Play: BaseRoomInfo, BaseUserList, Ready, Start
- Hosting: HostConnect, BattleStart
- User State (lobby/room/playing)
- TheRawServer.exe **dedicated handshake** (`CQ_TheRawServer_Connect = 0x410101`)
- Heartbeat / keep-alive

## State (in-memory)
- `clients     : Map<socket, ctx>`     — bağlı oyuncular
- `channels    : Map<channelId, {sockets}>` — kanal üyeleri (default 2 kanal)
- `rooms       : Map<roomId, {...}>`   — açık odalar
- `dedicateds  : Map<socket, dedi>`    — TheRawServer instance'ları

## Dedicated Handshake (TODO RE)
TheRawServer.exe lobby'e bağlanınca `0x410101` paketinde:
- roomId
- encryption key (per-session, dedicated tarafından üretilir)
- public IP + port

gönderir. Lobby bunu `dedicateds` map'ine kaydeder, oda Start basıldığında `SN_Hosting_BattleStart` paketinde dedicated IP+port'unu oyunculara verir.

**Tam payload layout henüz reverse edilmedi** — `handleDedicatedConnect()` içindeki tahmini layout düzeltilecek.

## Config
- `HOST`, `PORT`             — lobby dinleme
- `DEDI_PORT`                — dedicated server'ın TheRaw için bind ettiği port (default 3333)
- `DEFAULT_CHANNEL`          — kanal listesi boş olursa fallback

## Bilinen TODO / Açık Konular
- Hangar paketleri henüz "ack" — gerçek envanter parse edilmiyor
- ItemList / SlotInfo boş gönderiliyor (count=0); UI'de envanter ekranı boş
- Bazı paket ID çakışmaları doğrulanmalı (`SN_Room_ChangeLeader` vs `SN_Room_UserColorNickInfo` aynı 0x220319 — RE'de teyit)
- Şifresiz mod (sex.exe) için keyByte=0 fast-path eklenebilir (şu an brute force her seferinde key=0'ı 256. iterasyonda bulur)
