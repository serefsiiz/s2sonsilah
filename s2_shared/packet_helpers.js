'use strict';

// ==========================================================================
// S2: Hermit packet helpers + ack-only handler tables.
// Auth + Lobby ortak kullanır.
//
// "Ack-only handler" = client'tan gelen CQ_*'ye sadece "OK" cevap (errcode=0,
// reason=0) gönderir. Gerçek game logic implement edilmemiş paketler için.
// Bu sayede client "INVALID OPCODE" log'u atmaz, UI takılmaz.
// ==========================================================================

const PKT = require('./packet_ids');

// 6-byte error ack: u16 errcode + u32 reason (en yaygın SA_* formatı)
function buildErrorAck(errcode = 0, reason = 0) {
    const p = Buffer.alloc(6);
    p.writeUInt16LE(errcode, 0);
    p.writeUInt32LE(reason,  2);
    return p;
}

// Empty list payload: header byte + u8 count(0) — listenin boş olduğunu söyler
function buildEmptyList() {
    const p = Buffer.alloc(2);
    p[0] = 0;
    p[1] = 0;
    return p;
}

// CQ → SA mapping for packets that are ack-only (just OK reply, no payload)
// Client'tan gelen CQ_* opcode'unu hangi SA_* opcode'u ile cevaplayacağımız.
const CQ_TO_SA_ACK = {
    // Hangar/Equipment (zaten lobby'de açıkça implement edildi — burada sadece referans)
    [PKT.CQ_Hangar_Close]              : PKT.SA_Hangar_Close,
    [PKT.CQ_Hangar_ChangePart]         : PKT.SA_Hangar_ChangePart,
    [PKT.CQ_Hangar_Unequip]            : PKT.SA_Hangar_Unequip,

    // Hangar Nick change / check
    [PKT.CQ_Hangar_ChangeNickName]     : PKT.SA_Hangar_ChangeNickName,
    [PKT.CQ_Hangar_CheckNickName]      : PKT.SA_Hangar_CheckNickName,

    // Hangar Gift
    [PKT.CQ_Hangar_Gift_Send]          : PKT.SA_Hangar_Gift_Send,

    // Hangar RandomBox
    [PKT.CQ_Hangar_RandomBox_RewardList]: PKT.SA_Hangar_RandomBox_RewardList,

    // Hangar Convert
    [PKT.CQ_Hangar_Convert_MainSkinUse]: PKT.SA_Hangar_Convert_MainSkinUse,

    // Hangar Marble (gamble)
    [PKT.CQ_Hangar_Marble_WinnerList]      : PKT.SA_Hangar_Marble_WinnerList,
    [PKT.CQ_Hangar_Marble_SelectGamble]    : PKT.SA_Hangar_Marble_SelectGamble,
    [PKT.CQ_Hangar_Marble_UsePointLuckyShop]: PKT.SA_Hangar_Marble_UsePointLuckyShop,
    [PKT.CQ_Hangar_Marble_UseCashLuckyShop] : PKT.SA_Hangar_Marble_UseCashLuckyShop,

    // Channel detail / search / quick join
    [PKT.CQ_SearchUser]                : PKT.SA_SearchUser,
    [PKT.CQ_ViewDetailInfo]            : PKT.SA_ViewDetailInfo,
    [PKT.CQ_QuickJoin]                 : PKT.SA_QuickJoin,

    // Play
    [PKT.CQ_Play_ChangeWeapon]         : PKT.SA_Play_ChangeWeapon,
    [PKT.CQ_Play_ItemUse]              : PKT.SA_Play_ItemUse,

    // Friend
    [PKT.CQ_Friend_Delete]             : PKT.SA_Friend_Delete,

    // Mail
    [PKT.CQ_Mail_Send]                 : PKT.SA_Mail_Send,
    [PKT.CQ_Mail_ReadTag]              : PKT.SA_Mail_ReadTag,
    [PKT.CQ_Mail_Delete]               : PKT.SA_Mail_Delete,

    // Mail Gift
    [PKT.CQ_MailGift_ReceiveItem]      : PKT.SA_MailGift_ReceiveItem,
    [PKT.CQ_MailGift_Delete]           : PKT.SA_MailGift_Delete,

    // Tournament
    [PKT.CQ_Tournament_JoinList]       : PKT.SA_Tournament_JoinList,
    [PKT.CQ_Tournament_Update]         : PKT.SA_Tournament_Update,
    [PKT.CQ_Tournament_ProgressList]   : PKT.SA_Tournament_ProgressList,
    [PKT.CQ_Tournament_Progress]       : PKT.SA_Tournament_Progress,

    // QuickMatch (clan match)
    [PKT.CQ_QuickMatch_DetailView]     : PKT.SA_QuickMatch_DetailView,

    // Guild
    [PKT.CQ_Guild_Open]                : PKT.SA_Guild_Open,
    [PKT.CQ_Guild_Close]               : PKT.SA_Guild_Close,
    [PKT.CQ_Guild_Factory_Search]      : PKT.SA_Guild_Factory_Search,
    [PKT.CQ_Guild_Factory_CheckName]   : PKT.SA_Guild_Factory_CheckName,
    // [PKT.CQ_Guild_Factory_Create] — lobby'de gerçek handler var (clan persist + SN_UserInfo refresh)
    [PKT.CQ_Guild_Factory_SignupList]  : PKT.SA_Guild_Factory_SignupList,
    [PKT.CQ_Guild_Factory_Signup]      : PKT.SA_Guild_Factory_Signup,
    [PKT.CQ_Guild_Factory_Accept]      : PKT.SA_Guild_Factory_Accept,
    [PKT.CQ_Guild_Factory_Delete]      : PKT.SA_Guild_Factory_Delete,
    [PKT.CQ_Guild_Clanner_Delete]      : PKT.SA_Guild_Clanner_Delete,
    [PKT.CQ_Guild_Update_ChangeMarkPreCheck]: PKT.SA_Guild_Update_ChangeMarkPreCheck,
    [PKT.CQ_Guild_Update_ChangeMark]   : PKT.SA_Guild_Update_ChangeMark,
    [PKT.CQ_Guild_Update_ChangeNamePreCheck]: PKT.SA_Guild_Update_ChangeNamePreCheck,
    [PKT.CQ_Guild_Update_ChangeName]   : PKT.SA_Guild_Update_ChangeName,
    [PKT.CQ_Guild_Game_Together]       : PKT.SA_Guild_Game_Together,
    [PKT.CQ_Invite_Together]           : PKT.SA_Invite_Together,

    // Account create / nick
    [PKT.CQ_CreateUser]                : PKT.SA_CreateUser,
};

// CN_* / NN_* / SN_* paketleri (cevapsız) — sadece sessizce kabul et
const SILENT_OPCODES = new Set([
    PKT.CN_NetmarbleLoginData,
    PKT.CN_NetmarbleLoginPCInfo,
    PKT.CN_Play_ReadyButton,    // (lobby'de implement var — fallback)
    PKT.CN_Play_ExitButton,
    PKT.CN_QuickMatch_RegisterMatching,
    PKT.CN_QuickMatch_CancelMatching,
    PKT.CN_QuickMatch_BreakArenaRoom,
    PKT.CN_QuickMatch_ManualMatching,
    PKT.CN_QuickMatch_ManualMatchingResponse,
    PKT.CN_Friend_Add,
    PKT.CN_Friend_AddResponseFromTarget,
    PKT.CN_Friend_Chat,
    PKT.CN_Messenger_Load,
    PKT.CN_Messenger_Together,
    PKT.CN_Guild_InviteReject,
    PKT.CN_Guild_Game_Invite,
    PKT.CN_Guild_Game_Reject,
    PKT.CN_Chat_DevCommand,
    PKT.CQ_HackShield,
    PKT.CQ_Heartbeat,
    PKT.CQ_KeepAlive,
    PKT.CQ_KeepAliveAck,
    PKT.CQ_KeepAlive2,
    PKT.CQ_GameInit,
    PKT.CQ_Mail_Refresh,
    PKT.CQ_MailGift_Refresh,
]);

// Auth-server-only ack mapping (login alternatifleri)
const CQ_TO_SA_ACK_AUTH = {
    [PKT.CQ_Login]       : PKT.SA_Login,
    [PKT.CQ_MenaLogin]   : PKT.SA_MenaLogin,
    // Netmarble/Global login: client 'success' tek-byte payload bekleyebilir
    // ama errcode=0 reason=0 ile çalışıyor.
};

module.exports = {
    buildErrorAck,
    buildEmptyList,
    CQ_TO_SA_ACK,
    CQ_TO_SA_ACK_AUTH,
    SILENT_OPCODES,
};
