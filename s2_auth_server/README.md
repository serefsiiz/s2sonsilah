# S2 Auth Server

Port: **12000**

## Çalıştır
```
cd s2_auth_server
npm install
npm start
```

## Sorumluluk
- `CQ_JoyGameLogin` / `CQ_Join` → login
- `SN_UserInfo`, `SN_Record` → kullanıcı özeti
- `SN_ServerList`, `SN_ServerInfo`, `SN_ChannelList` → sunucu/kanal seçim ekranı
- `CQ_AwayUser` → `SA_AwayUser` ile lobby IP+port döndürür
- Heartbeat / keep-alive

## Akış
```
Client (TheRaw.exe gs_port 12000)
   ↓ CQ_JoyGameLogin
Auth ──→ SA_JoyGameLogin + UserInfo + Record + ServerList + ServerInfo + ChannelList
   ↓ kullanıcı sunucu seçince
Client → CQ_AwayUser
Auth   → SA_AwayUser  (lobby IP=127.0.0.1 port=13000)
   ↓
Client yeni TCP soketi açar → s2_lobby_server (13000)
```

## Config
Düzenlenecek değerler `index.js` üstündeki `CONFIG` bloğunda:
- `HOST`, `PORT`
- `LOBBY_HOST`, `LOBBY_PORT` (server seçim cevabında geçer)
