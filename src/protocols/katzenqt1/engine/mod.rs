//! A katzenqt1 group chat client without IO: [`Engine::step`] takes the state and one input, from
//! the user or from the network, and returns the network work it asks for and what changed. The
//! caller saves what changed before it carries out any of the work.
//!
//! The member state machine is driven as katzenqt's adapter drives it: compose for each message
//! sent, written once its box is written, observe for each box read in order, handle for a new
//! epoch and for a user's scan, and for a new member begin_induction, then once everything owed
//! is written reply, then introduce_now as soon as the reply is sealed, ahead of anything sent
//! while it sealed, so that the Introduction is the box at the index the reply names.

mod core;
mod io;
mod notice;
mod state;

pub use crate::protocols::katzenqt1::engine::core::{Engine, WINDOW, backoff, sanitize, voucher_code};
pub use io::{Action, Changes, FileWrite, Input, Outcome, StepResult};
pub use notice::{Notice, NoticeKind, plain, size_text};
pub use state::{
    Attachment, Chat, ChatId, Download, Inducting, Job, Joining, Line, MAX_LOG, Sealed, State,
    Status, Upload,
};
