/// What the client tells the user of a conversation, as a kind and its arguments; an app words it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub kind: NoticeKind,
    pub args: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    NameTaken,
    NameTakenJoining,
    Minting,
    NewGroup,
    /// Its arguments are the code, the group's name and the file holding the code.
    VoucherMinted,
    ReplyUnreadable,
    Joined,
    NotJoinedYet,
    AlreadyAdding,
    NotAVoucher,
    ReadingVoucher,
    /// Its argument is whom it added.
    Added,
    NotJoined,
    FileTooLarge,
    SendLost,
    FileTooLargeToFetch,
    Scanning,
    NoLongerMember,
    StoppedReading,
    Renamed,
    /// Its argument says what failed.
    ActionFailed,
    TooLong,
    NotWritten,
    /// Its arguments are who added whom.
    MemberAdded,
    Unreadable,
    NotFetched,
    /// A box of our stream holds other bytes than we meant to write there: another client writes
    /// our stream, or this state is older than one that wrote it.
    Desync,
}

impl NoticeKind {
    pub fn code(self) -> u32 {
        self as u32
    }

    pub fn from_code(c: u32) -> Option<NoticeKind> {
        use NoticeKind::*;
        [
            NameTaken,
            NameTakenJoining,
            Minting,
            NewGroup,
            VoucherMinted,
            ReplyUnreadable,
            Joined,
            NotJoinedYet,
            AlreadyAdding,
            NotAVoucher,
            ReadingVoucher,
            Added,
            NotJoined,
            FileTooLarge,
            SendLost,
            FileTooLargeToFetch,
            Scanning,
            NoLongerMember,
            StoppedReading,
            Renamed,
            ActionFailed,
            TooLong,
            NotWritten,
            MemberAdded,
            Unreadable,
            NotFetched,
            Desync,
        ]
        .get(c as usize)
        .copied()
    }
}

/// A notice worded as group_chat_client's plain presentation does, with names as they are.
pub fn plain(n: &Notice) -> String {
    use NoticeKind::*;
    let a = |i: usize| n.args.get(i).map(String::as_str).unwrap_or("");
    match n.kind {
        NameTaken => format!("you already have a group called {}", a(0)),
        NameTakenJoining => format!(
            "you already have a group called {}: to join someone else's group, give it a name of its own",
            a(0)
        ),
        Minting => "minting a voucher".into(),
        NewGroup => "a new group: adding a member's voucher code adds them".into(),
        VoucherMinted => format!(
            "give the voucher code to a member of the group (it is also in {})",
            a(2)
        ),
        ReplyUnreadable => "the reply to our voucher cannot be read".into(),
        Joined => "joined the group".into(),
        NotJoinedYet => "join or create the group first".into(),
        AlreadyAdding => "already adding a member".into(),
        NotAVoucher => "that is not a voucher code".into(),
        ReadingVoucher => "reading the voucher".into(),
        Added => format!(
            "added ~{}: they now read everything said in this group",
            a(0)
        ),
        NotJoined => "this conversation has not been joined yet".into(),
        FileTooLarge => format!("that file is too large to send: at most {}", a(0)),
        SendLost => "a message could not be sent: what it held was lost".into(),
        FileTooLargeToFetch => format!("{} sent a file too large to fetch", a(0)),
        Scanning => "scanning for missed messages".into(),
        NoLongerMember => "that member is no longer in this group".into(),
        StoppedReading => format!(
            "stopped reading {} and deleted what they sent; they can still read this group",
            a(0)
        ),
        Renamed => format!("renamed from {}", a(0)),
        ActionFailed => a(0).into(),
        TooLong => "that message is too long to send".into(),
        NotWritten => "a message could not be written".into(),
        MemberAdded => format!("{} added ~{}", a(0), a(1)),
        Unreadable => format!("{} sent a message that cannot be read", a(0)),
        NotFetched => format!("{} sent a message that could not be fetched", a(0)),
        Desync => {
            "a box of our stream holds something else: is this group used from another client?"
                .into()
        }
    }
}

/// A size as people read it.
pub fn size_text(n: usize) -> String {
    const MB: usize = 1024 * 1024;
    if n < 1024 {
        format!("{n} bytes")
    } else if n < MB {
        format!("{} KB", (n + 512) / 1024)
    } else {
        format!("{}.{} MB", n / MB, n % MB * 10 / MB)
    }
}
