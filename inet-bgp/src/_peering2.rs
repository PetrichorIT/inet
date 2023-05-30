// May be in further changes
enum _Event {
    ManualStart = 1,
    ManualStop = 2,
    AutomaticStart = 3,
    ManualStartWithPassivTcpEstablishment = 4,
    AutomaticStartWithPassivTcpEstablishment = 5,
    AutomaticStartWithDampPeerOscillations = 6,
    AutomaticStartWithDampePeerOciallationsAndPassivTcpEstablishment = 7,
    AutomaticStop = 8,

    ConnectRetryTimerExpired = 9,
    HoldTimerExpired = 10,
    KeepaliveTimerExpired = 11,
    DelayOpenTimerExpired = 12,
    IdleHoldTimerExpired = 13,

    TcpConnectionValid = 14,
    TcpCRInvalid = 15,
    TcpCRAcked = 16,
    TcpConnectionConfirmed = 17,
    TcpConnectionFailed = 18,

    BgpOpen = 19,
    BgpOpenWithDelayTimerRunning = 20,
    BgpHeaderError = 21,
    BgpOpenMessageError = 22,
    OpenCollisionDump = 23,
    NotificationMessageVersionError = 24,
    NotificationMessageError = 25,
    Keepalive,
    Update,
    UpdateMessageError,
}

#[repr(u8)]
enum _Event2 {
    ManualStart {
        passiv_tcp_establishment: bool,
    },
    ManualStop,
    AutomaticStart {
        passiv_tcp_establishment: bool,
        damp_peer_oscillations: bool,
    } = 3,
    AutomaticStop,

    ConnectRetryTimerExpired,
    HoldTimerExpired,
    KeepaliveTimerExpired,
    DelayOpenTimerExpired,
    IdleHoldTimerExpired,

    TcpConnectionValid,
    TcpCRInvalid,
    TcpCRAcked,
    TcpConnectionConfirmed,
    TcpConnectionFailed,

    BgpHeaderError,
    BgpOpen {
        delay_timer_running: bool,
        collision_dump: bool,
        open: Result<BgpOpenPacket>,
    },

    NotificationMessageError {
        notif: BgpNotificationPacket,
    },
    Keepalive,
    Update {
        update: Result<BgpUpdatePacket>,
    },
}
