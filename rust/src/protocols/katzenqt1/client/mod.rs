//! A katzenqt1 group chat client: the engine, its state on disk, and its work carried out over a
//! transport.

mod chat;
pub mod exec;
pub mod seal;
pub mod sealed_file;
pub mod store;

pub use chat::{ChatView, Client, ClientError, Config, Event, LineView, MemberView};

pub use exec::{Executor, Files, Outcome, RETRY_MS};
