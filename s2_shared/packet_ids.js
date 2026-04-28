'use strict';

// ==========================================================================
// S2: TÜM bilinen paket ID'leri.
// Kaynak: GameClient.dll sub_100570D0 dispatcher (debug-name printer).
// Auth + Lobby ortak kullanır.
//
// Naming convention: ModuleNS_DIRECTION_Name
//   CQ = Client→Server Query (cevap bekler)
//   SA = Server→Client Answer (CQ cevabı)
//   CN = Client→Server Notify (cevap yok)
//   SN = Server→Client Notify (push)
//   NN = Server↔Client iki yönlü (chat vb.)
//
// Dispatcher reverse — ham string format'ı:
//   "tPacket_<Module>_<SubModule>_<DIR>_<Name>"
// Bu dosyada Module+SubModule kısalması var; tam liste için PKT_NAMES'e bak.
// ==========================================================================

const PKT = {
    // ============================================================
    // NAccount/NIdentity (login + auth)
    // ============================================================
    CQ_Login                            : 0x110101,
    SA_Login                            : 0x110102,
    CQ_JoyGameLogin                     : 0x110111,
    SA_JoyGameLogin                     : 0x110112,
    CN_NetmarbleLoginData               : 0x110121,
    CN_NetmarbleLoginPCInfo             : 0x110122,
    SA_NetmarbleLogin                   : 0x110123,
    CQ_Join                             : 0x110124,
    SA_Join                             : 0x110125,
    SA_GlobalLogin                      : 0x110142,    // dispatcher'da yok ama mevcut
    SN_Order                            : 0x110131,
    CQ_MenaLogin                        : 0x110151,
    SA_MenaLogin                        : 0x110152,

    // ============================================================
    // NLaunch/NLock (login bundle data)
    // ============================================================
    SN_UserInfo                         : 0x210101,
    SN_Record                           : 0x210103,
    SN_RankingInfo                      : 0x210105,
    SN_ItemList                         : 0x210111,
    SN_SlotInfo                         : 0x210113,
    SN_LockEnd                          : 0x210121,
    SN_MainWeaponList                   : 0x210122,
    SN_RecordMapList                    : 0x210123,
    SN_ShotdownToYouth                  : 0x210131,
    SN_NetCafeInfo                      : 0x210141,
    SN_ChatPunishInfo                   : 0x210151,
    SN_ChangeNickNameColor              : 0x210152,    // NMatchup/NUser

    // ============================================================
    // NLaunch/NFactory (account create / nick)
    // ============================================================
    CQ_CreateUser                       : 0x210201,
    SA_CreateUser                       : 0x210202,
    SA_ChangeNickName                   : 0x210222,

    // ============================================================
    // NMatchup/NChannel (server + channel listing)
    // ============================================================
    SN_ServerInfo                       : 0x220101,
    SN_ChannelList                      : 0x220102,
    SN_GroupList                        : 0x220107,
    SN_ServerList                       : 0x220108,
    CQ_Channel_EnterUser                : 0x220111,
    SA_Channel_EnterUser                : 0x220112,
    SN_Channel_UserList                 : 0x220113,
    CQ_Channel_LeaveUser                : 0x220114,
    SA_Channel_LeaveUser                : 0x220115,
    SN_Channel_LeaveUser                : 0x220116,
    CQ_SearchUser                       : 0x220121,
    SA_SearchUser                       : 0x220122,
    CQ_AwayUser                         : 0x220131,
    SA_AwayUser                         : 0x220132,
    CQ_ViewDetailInfo                   : 0x220151,
    SA_ViewDetailInfo                   : 0x220152,
    SN_ViewDetailInfo_Diary             : 0x220153,
    SN_ViewDetailInfo_Progress          : 0x220154,
    CQ_QuickJoin                        : 0x220161,
    SA_QuickJoin                        : 0x220162,

    // ============================================================
    // NMatchup/NRoom (oda yönetimi)
    // ============================================================
    CQ_Room_Create                      : 0x220201,
    SA_Room_Create                      : 0x220202,
    SN_Room_Info                        : 0x220203,
    SN_Room_UpdateInfoToChannelUser     : 0x220204,
    CQ_Room_ChangeBoundary              : 0x220211,
    SA_Room_ChangeBoundary              : 0x220212,
    SN_Room_ChangeBoundary              : 0x220213,
    SN_Room_ChangeRoomState             : 0x220214,
    CQ_Room_ChangeOption                : 0x220215,
    SA_Room_ChangeOption                : 0x220216,
    SN_Room_ChangeOption                : 0x220217,
    CQ_Room_ChangeName                  : 0x220218,
    SA_Room_ChangeName                  : 0x220219,
    SN_Room_ChangeName                  : 0x22021A,
    CQ_Room_ChangePassword              : 0x22021B,
    SA_Room_ChangePassword              : 0x22021C,
    CQ_Room_ChangeMapInfo               : 0x220221,
    SA_Room_ChangeMapInfo               : 0x220222,
    SN_Room_ChangeMapInfo               : 0x220223,
    CQ_Room_EnterUser                   : 0x220231,
    SA_Room_EnterUser                   : 0x220232,
    SN_Room_UserList                    : 0x220233,
    CQ_Room_LeaveUser                   : 0x220234,
    SA_Room_LeaveUser                   : 0x220235,
    SN_Room_LeaveUser                   : 0x220236,
    CQ_Room_CompulsionAway              : 0x220237,
    SA_Room_CompulsionAway              : 0x220238,
    SN_Room_UserColorNickInfo           : 0x220239,

    // ============================================================
    // NMatchup/NTeam (takım yönetimi)
    // ============================================================
    CQ_Team_Change                      : 0x220311,
    SA_Team_Change                      : 0x220312,
    SN_Team_Change                      : 0x220313,
    CN_Team_Exchange                    : 0x220314,
    SA_Team_Exchange                    : 0x220315,
    SN_Team_Exchange                    : 0x220316,
    CQ_Team_ChangeLeader                : 0x220317,
    SN_Team_ChangeLeader                : 0x220319,
    SN_Team_ChangeTeamLeader            : 0x22031A,

    // ============================================================
    // NMatchup/NUser
    // ============================================================
    SN_User_State                       : 0x220401,
    SN_User_UserLevel                   : 0x220411,
    SN_User_Record                      : 0x220412,
    SN_User_ChangeNickName              : 0x220421,
    SN_User_ChangeTitle                 : 0x220431,

    // ============================================================
    // NMatchup/NChat
    // ============================================================
    NN_Chat_WaitRoom                    : 0x220501,
    NN_Chat_ChattingFail                : 0x220502,
    NN_Chat_NotBattleTeam               : 0x220503,
    NN_Chat_NotBattleAll                : 0x220505,
    NN_Chat_BattleTeam                  : 0x220507,
    NN_Chat_BattleAll                   : 0x220509,
    NN_Chat_BattleTeamRadio             : 0x220510,
    CQ_Chat_Whisper                     : 0x220511,
    SN_Chat_Whisper                     : 0x220513,
    CN_Chat_DevCommand                  : 0x220522,
    SN_Chat_DevCommandFail              : 0x220523,
    SN_Chat_ChatPunish                  : 0x220531,

    // ============================================================
    // NMatchup/NAdvertise + NEvent
    // ============================================================
    SN_Adv_Notice                       : 0x221401,
    SN_Event_MapEventInfo               : 0x221501,
    SN_Event_EventMap                   : 0x221502,

    // ============================================================
    // NMatchup/NInvite
    // ============================================================
    SA_Invite_UserList                  : 0x221E02,
    SN_Invite_UserList                  : 0x221E03,
    SN_Invite_Invite                    : 0x221E05,
    SN_Invite_Reject                    : 0x221E07,
    CQ_Invite_Together                  : 0x221E11,
    SA_Invite_Together                  : 0x221E12,

    // ============================================================
    // NMatchup/NPlay (ready/start/exit/weapon/item)
    // ============================================================
    CN_Play_ReadyButton                 : 0x222101,
    SN_Play_ReadyButtonFail             : 0x222102,
    CN_Play_StartButton                 : 0x222103,
    SN_Play_StartButtonFail             : 0x222104,
    SN_Play_LocalKey                    : 0x222105,
    SN_Play_BaseRoomInfo                : 0x222111,
    SN_Play_BaseUserList                : 0x222112,
    SN_Play_BattleInfo                  : 0x222114,
    SN_Play_ExchangeTeam                : 0x222121,
    SN_Play_ExchangeRule                : 0x222122,
    CN_Play_ExitButton                  : 0x222131,
    SN_Play_ExitButton                  : 0x222132,
    CQ_Play_ChangeWeapon                : 0x222141,
    SA_Play_ChangeWeapon                : 0x222142,
    SN_Play_ChangeWeapon                : 0x222143,
    CQ_Play_ItemUse                     : 0x222151,
    SA_Play_ItemUse                     : 0x222152,
    SN_Play_EndRoundPlayTime            : 0x222153,

    // ============================================================
    // NMatchup/NResult — dispatcher decimal→hex (önceki +0x100 yanlıştı):
    //   2236948=0x222214, 2236961=0x222221, 2236993=0x222241, 2237009=0x222251
    // ============================================================
    SN_Result_UserScore                 : 0x222214,
    SN_Result_GameFinalResult           : 0x222221,
    SN_Result_MapEventReward            : 0x222241,
    SN_Result_PCRoomMileage             : 0x222251,

    // ============================================================
    // NTournament/NGame — dispatcher 2237441 = 0x222401 (NOT 0x222301!)
    // ============================================================
    CQ_Tournament_JoinList              : 0x222401,
    SA_Tournament_JoinList              : 0x222402,
    SN_Tournament_JoinList              : 0x222403,
    SN_Tournament_JoinClannerList       : 0x222404,
    CQ_Tournament_Update                : 0x222405,
    SA_Tournament_Update                : 0x222406,
    CQ_Tournament_ProgressList          : 0x222411,
    SA_Tournament_ProgressList          : 0x222412,
    SN_Tournament_ProgressList          : 0x222413,
    CQ_Tournament_Progress              : 0x222414,
    SA_Tournament_Progress              : 0x222415,
    SN_Tournament_Progress              : 0x222416,
    SN_Tournament_ExecuteRoomFail       : 0x222421,
    SN_Tournament_NoticeList            : 0x222422,
    SN_Tournament_RewardList            : 0x222423,

    // ============================================================
    // NMatchup/NQuickMatch (clan match / arena)
    // dispatcher 2240769 = 0x223101 (NOT 0x222301 — apayrı modül)
    // ============================================================
    CN_QuickMatch_RegisterMatching      : 0x223101,
    SN_QuickMatch_RegisterMatching      : 0x223102,
    SN_QuickMatch_CompleteMatching      : 0x223103,
    SN_QuickMatch_MatchingConditionList : 0x223104,
    CN_QuickMatch_CancelMatching        : 0x223111,
    SN_QuickMatch_CancelMatching        : 0x223112,
    SN_QuickMatch_InitializeMatching    : 0x223113,
    CN_QuickMatch_BreakArenaRoom        : 0x223114,
    SN_QuickMatch_BreakArenaRoom        : 0x223115,
    SN_QuickMatch_InitializeArenaRoom   : 0x223116,
    CQ_QuickMatch_DetailView            : 0x223121,
    SA_QuickMatch_DetailView            : 0x223122,
    CN_QuickMatch_ManualMatching        : 0x223131,
    SN_QuickMatch_ManualMatching        : 0x223132,
    SN_QuickMatch_ManualMatchingRequest : 0x223133,
    CN_QuickMatch_ManualMatchingResponse: 0x223134,
    SN_QuickMatch_ManualMatchingResponseFail: 0x223135,

    // ============================================================
    // NBattle/NGame (in-game events)
    // ============================================================
    SN_Battle_Revive                    : 0x230104,
    SN_Battle_Kill                      : 0x230124,
    SN_Battle_Bomb                      : 0x230136,
    SN_Battle_FlexibleCapture           : 0x230142,
    SN_Battle_Captin                    : 0x230151,
    SN_Battle_Escape                    : 0x230162,

    // ============================================================
    // NHangar/NEquipment (envanter / loadout)
    // ============================================================
    CQ_Hangar_Open                      : 0x240101,
    SA_Hangar_Open                      : 0x240102,
    CQ_Hangar_Close                     : 0x240103,
    SA_Hangar_Close                     : 0x240104,
    CQ_Hangar_ChangePart                : 0x240107,
    SA_Hangar_ChangePart                : 0x240108,
    CQ_Hangar_ActiveItem                : 0x240121,
    SA_Hangar_ActiveItem                : 0x240122,
    CQ_Hangar_DeleteItem                : 0x240123,
    SA_Hangar_DeleteItem                : 0x240124,
    CQ_Hangar_UseItem                   : 0x240125,
    SA_Hangar_UseItem                   : 0x240126,
    SN_PackageItem                      : 0x240131,    // dispatcher: tPacket_Hanger_NEquiment_SN_PackageItem
    CQ_Hangar_Unequip                   : 0x240161,
    SA_Hangar_Unequip                   : 0x240162,

    // ============================================================
    // NHangar/NPurchase (satın alma)
    // ============================================================
    CQ_Hangar_Buy                       : 0x240201,
    SA_Hangar_Buy                       : 0x240202,
    CQ_Hangar_CashBuy                   : 0x240203,
    SA_Hangar_CashBuy                   : 0x240204,
    CQ_Hangar_CashReLoad                : 0x240211,
    SA_Hangar_CashReLoad                : 0x240212,
    SN_Hangar_CashReLoad                : 0x240213,

    // ============================================================
    // NHangar (üst seviye / nick / destroy / gift)
    // ============================================================
    SN_Hangar_LimitItemDestory          : 0x240601,
    CQ_Hangar_ChangeNickName            : 0x240301,
    SA_Hangar_ChangeNickName            : 0x240302,
    CQ_Hangar_CheckNickName             : 0x240303,
    SA_Hangar_CheckNickName             : 0x240304,
    CQ_Hangar_Gift_Send                 : 0x240511,
    SA_Hangar_Gift_Send                 : 0x240512,
    SN_Hangar_Gift_Send                 : 0x240513,

    // ============================================================
    // NHangar/NMarble (gamble)
    // ============================================================
    CQ_Hangar_Marble_WinnerList         : 0x240701,
    SA_Hangar_Marble_WinnerList         : 0x240702,
    SN_Hangar_Marble_WinnerList         : 0x240703,
    SN_Hangar_Marble_RewardItem         : 0x240704,
    SN_Hangar_Marble_Winner             : 0x240705,
    CQ_Hangar_Marble_SelectGamble       : 0x240706,
    SA_Hangar_Marble_SelectGamble       : 0x240707,
    CQ_Hangar_Marble_UsePointLuckyShop  : 0x240708,
    SA_Hangar_Marble_UsePointLuckyShop  : 0x240709,
    CQ_Hangar_Marble_UseCashLuckyShop   : 0x240710,
    SA_Hangar_Marble_UseCashLuckyShop   : 0x240711,
    SN_Hangar_Marble_LuckyRewardItem    : 0x240712,
    SN_Hangar_Marble_LuckyWinnerList    : 0x240713,
    SN_Hangar_Marble_LuckyWinner        : 0x240714,

    // ============================================================
    // NHangar/NRandomBox + NConvert
    // ============================================================
    CQ_Hangar_RandomBox_RewardList      : 0x240801,
    SA_Hangar_RandomBox_RewardList      : 0x240802,
    SN_Hangar_RandomBox_RewardItem      : 0x240803,
    CQ_Hangar_Convert_MainSkinUse       : 0x240901,
    SA_Hangar_Convert_MainSkinUse       : 0x240902,

    // ============================================================
    // NAchievement/NData
    // ============================================================
    SN_Achievement_BaseInfo             : 0x2A0101,
    SN_Achievement_Diary                : 0x2A0102,
    SN_Achievement_Progress             : 0x2A0103,

    // ============================================================
    // NMailBox/NMail (mail kutusu) — dispatcher TEYİTLİ:
    //   cmp esi,310201h → "tPacket_NMailBox_NMail_SN_Info"
    // ============================================================
    SN_Mail_Info                        : 0x310201,
    SN_Mail_Mail                        : 0x310202,
    CQ_Mail_Send                        : 0x310211,
    SA_Mail_Send                        : 0x310212,
    SN_Mail_Send                        : 0x310213,
    CQ_Mail_ReadTag                     : 0x310214,
    SA_Mail_ReadTag                     : 0x310215,
    CQ_Mail_Refresh                     : 0x310216,
    CQ_Mail_Delete                      : 0x310218,
    SA_Mail_Delete                      : 0x310219,

    // ============================================================
    // NMailBox/NGift — dispatcher: cmp esi,310301h → "NGift_SN_Info"
    // ============================================================
    SN_MailGift_Info                    : 0x310301,
    SN_MailGift_Gift                    : 0x310302,
    CQ_MailGift_ReceiveItem             : 0x310316,
    SA_MailGift_ReceiveItem             : 0x310317,
    CQ_MailGift_Refresh                 : 0x310318,
    CQ_MailGift_Delete                  : 0x31031A,
    SA_MailGift_Delete                  : 0x31031B,

    // ============================================================
    // NMessanger/NData + NFriend + NGame
    // ============================================================
    SN_Messenger_FriendList             : 0x320101,
    SN_Messenger_NotHaveFriend          : 0x320102,
    SN_Messenger_NotLoad                : 0x320103,
    CN_Messenger_Load                   : 0x320104,
    CN_Friend_Add                       : 0x320201,
    SN_Friend_AddResult                 : 0x320202,
    SN_Friend_AddRequestToTarget        : 0x320203,
    CN_Friend_AddResponseFromTarget     : 0x320204,
    SN_Friend_AddResponseToTarget       : 0x320205,
    SN_Friend_AddNotifyToRequester      : 0x320206,
    CQ_Friend_Delete                    : 0x320208,
    SA_Friend_Delete                    : 0x320209,
    SN_Friend_DeleteNotify              : 0x320210,
    CN_Friend_Chat                      : 0x320211,
    SN_Friend_Chat                      : 0x320212,
    SN_Friend_Online                    : 0x320213,
    SN_Friend_Offline                   : 0x320214,
    SN_Friend_ChangeClanInfo            : 0x320221,
    SN_Friend_ChangeNickName            : 0x320231,
    SN_Friend_ChangeLevel               : 0x320232,
    SN_Friend_ChangeColor               : 0x320233,
    CN_Messenger_Together               : 0x320301,
    SN_Messenger_Together               : 0x320302,

    // ============================================================
    // NGuild/NInit
    // ============================================================
    SN_Guild_LoadFail                   : 0x360102,
    SN_Guild_NotClanner                 : 0x360103,
    SN_Guild_ClanServerDisconnect       : 0x360105,
    CQ_Guild_Open                       : 0x360111,
    SA_Guild_Open                       : 0x360112,
    CQ_Guild_Close                      : 0x360121,
    SA_Guild_Close                      : 0x360122,

    // ============================================================
    // NGuild/NFactory (klan kurma + signup)
    // ============================================================
    CQ_Guild_Factory_Search             : 0x360201,
    SA_Guild_Factory_Search             : 0x360202,
    CQ_Guild_Factory_CheckName          : 0x360211,
    SA_Guild_Factory_CheckName          : 0x360212,
    CQ_Guild_Factory_Create             : 0x360221,
    SA_Guild_Factory_Create             : 0x360222,
    CQ_Guild_Factory_SignupList         : 0x360241,
    SA_Guild_Factory_SignupList         : 0x360242,
    CQ_Guild_Factory_Signup             : 0x360251,
    SA_Guild_Factory_Signup             : 0x360252,
    SN_Guild_Factory_Signup             : 0x360253,
    CQ_Guild_Factory_Accept             : 0x360261,
    SA_Guild_Factory_Accept             : 0x360262,
    SN_Guild_Factory_Accept             : 0x360263,
    SN_Guild_Factory_SignerAccept       : 0x360264,
    CQ_Guild_Factory_Delete             : 0x360271,
    SA_Guild_Factory_Delete             : 0x360272,
    SN_Guild_Factory_Delete             : 0x360273,
    SN_Guild_Factory_Reject             : 0x360274,
    SN_Guild_Factory_SignerReject       : 0x360275,

    // ============================================================
    // NGuild/NData
    // ============================================================
    SN_Guild_ClannerList                : 0x360302,
    SN_Guild_SignupList                 : 0x360303,

    // ============================================================
    // NGuild/Nclanner + NClanner
    // ============================================================
    SN_Guild_Clanner_Online             : 0x360401,
    SN_Guild_Clanner_Offline            : 0x360402,
    SN_Guild_Clanner_AddClanner         : 0x360414,
    SN_Guild_Clanner_ChangeTitle        : 0x360416,
    SN_Guild_Clanner_ChangeColor        : 0x360417,
    CQ_Guild_Clanner_Delete             : 0x360421,
    SA_Guild_Clanner_Delete             : 0x360422,
    SN_Guild_Clanner_Secede             : 0x360423,
    SN_Guild_Clanner_Kick               : 0x360424,
    SN_Guild_Clanner_ListInChannel      : 0x360461,
    SN_Guild_Clanner_ListInRoom         : 0x360462,
    SN_Guild_Clanner_DeleteInfoInChannel: 0x360463,
    SN_Guild_Clanner_DeleteInfoInRoom   : 0x360464,

    // ============================================================
    // NGuild/NUpdate (klan adı + işareti değişikliği)
    // ============================================================
    CQ_Guild_Update_ChangeMarkPreCheck  : 0x360501,
    SA_Guild_Update_ChangeMarkPreCheck  : 0x360502,
    CQ_Guild_Update_ChangeMark          : 0x360503,
    SA_Guild_Update_ChangeMark          : 0x360504,
    SN_Guild_Update_ChangeMark          : 0x360505,
    CQ_Guild_Update_ChangeNamePreCheck  : 0x360511,
    SA_Guild_Update_ChangeNamePreCheck  : 0x360512,
    CQ_Guild_Update_ChangeName          : 0x360513,
    SA_Guild_Update_ChangeName          : 0x360514,
    SN_Guild_Update_ChangeName          : 0x360515,
    SN_Guild_Update_ChangeNickName      : 0x360531,
    SN_Guild_Update_UpdateClanLevel     : 0x360551,
    SN_Guild_Update_ResetClanRecord     : 0x360552,

    // ============================================================
    // NGuild/NInvite
    // ============================================================
    SA_Guild_Invite_Invite              : 0x360602,
    SN_Guild_Invite_InviteToUser        : 0x360603,
    CN_Guild_Invite_Reject              : 0x360604,
    SN_Guild_Invite_Reject              : 0x360605,

    // ============================================================
    // NGuild/NBattle
    // ============================================================
    SN_Guild_Battle_ClanRecordNotify    : 0x360801,
    SN_Guild_Battle_ClannerRecordNotify : 0x360802,

    // ============================================================
    // NGuild/NGame (klan davet + together)
    // ============================================================
    CN_Guild_Game_Invite                : 0x360F01,
    SN_Guild_Game_Invite                : 0x360F02,
    SN_Guild_Game_InviteFail            : 0x360F03,
    CN_Guild_Game_Reject                : 0x360F11,
    SN_Guild_Game_Reject                : 0x360F12,
    CQ_Guild_Game_Together              : 0x360F21,
    SA_Guild_Game_Together              : 0x360F22,
    CQ_Invite_Together                  : 0x221E11,    // (alias / cross-mod)

    // ============================================================
    // NHosting (dedi server bağlantı + battle)
    // CanHostSyn dispatcher 4325889 = 0x420201 (önceki 0x420101 yanlıştı)
    // CN_TheRawServer_RoundStart KALDIRILDI: 0x230151 = SN_Battle_Captin
    //   (dedi server SN_Captin paketini lobby'ye gönderiyor; "RoundStart"
    //    benim ad-hoc tahminimdi, doğrusu Captain mode notify)
    // ============================================================
    CN_TheRawServer_Connect             : 0x410101,    // dedi → lobby handshake (Hermit-only opcode)
    CN_TheRawServer_Ready1              : 0x420203,    // dedi notify (handshake aşaması)
    CN_TheRawServer_Ready2              : 0x420204,
    CN_TheRawServer_Ready3              : 0x420206,
    Hosting_CanHostSyn                  : 0x420201,
    SN_Hosting_Waiting                  : 0x420301,
    SN_Hosting_HostingFail              : 0x420302,
    SN_Hosting_HostConnect              : 0x420303,
    SN_Hosting_BattleStart              : 0x420310,
    SN_Hosting_UserExit                 : 0x420320,
    SN_Hosting_HostDisConnect           : 0x420321,

    // ============================================================
    // NInspector/NChannel + NInit (admin)
    // ============================================================
    SN_Inspector_Login                  : 0x510101,
    SN_Inspector_AllNotify              : 0x510203,

    // ============================================================
    // HackShield + Heartbeat / KeepAlive
    // ============================================================
    CQ_HackShield                       : 0x750101,
    CQ_Heartbeat                        : 0x20080,
    SA_HeartbeatAck                     : 0x20081,
    CQ_KeepAlive                        : 0x20082,
    SA_KeepAliveAck                     : 0x20083,
    CQ_KeepAlive2                       : 0x20084,
    CQ_GameInit                         : 0x130000,
};

module.exports = PKT;

// --------------------------------------------------------------------------
// Reverse lookup: opcode → "MODULE_DIR_NAME" string
// Lobby/Auth log'larda 0x220203 yerine "SN_Room_Info" yazdırmak için.
// İki opcode aynı sayıya denk geliyorsa (tournament/quickmatch çakışması)
// ilk eşleşeni yazar; debug için yeterli.
// --------------------------------------------------------------------------
const _PKT_NAMES = (() => {
    const m = new Map();
    for (const [name, id] of Object.entries(PKT)) {
        if (!m.has(id)) m.set(id, name);
    }
    return m;
})();

module.exports.NAME = function(opcode) {
    return _PKT_NAMES.get(opcode) || `0x${opcode.toString(16)}`;
};
