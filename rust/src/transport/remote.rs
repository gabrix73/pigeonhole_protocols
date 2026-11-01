//! A Pigeonhole served from another process, as JSON-RPC 1.0 over a unix socket: what the Go
//! module's transport/remote serves, so that clients in Go and in Rust share one in-memory
//! Pigeonhole in tests.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::transport::{Backend, Error, Inducted, Keypair, Minted, Opened, Read, Result, Secret};

pub struct Remote {
    pub socket: PathBuf,
}

fn b64(b: &[u8]) -> Value {
    Value::String(STANDARD.encode(b))
}

fn bytes(v: &Value) -> Vec<u8> {
    v.as_str()
        .and_then(|s| STANDARD.decode(s).ok())
        .unwrap_or_default()
}

fn other(e: impl std::fmt::Display) -> Error {
    Error::Other(e.to_string())
}

impl Remote {
    async fn call(&self, method: &str, a: Value) -> Result<Value> {
        let mut s = UnixStream::connect(&self.socket).await.map_err(other)?;
        let req = json!({"method": format!("Pigeonhole.{method}"), "params": [a], "id": 1});
        let mut line = serde_json::to_vec(&req).unwrap();
        line.push(b'\n');
        s.write_all(&line).await.map_err(other)?;
        let mut r = BufReader::new(s);
        let mut resp = String::new();
        r.read_line(&mut resp).await.map_err(other)?;
        let v: Value = serde_json::from_str(&resp).map_err(other)?;
        if !v["error"].is_null() {
            return Err(Error::Other(v["error"].to_string()));
        }
        Ok(v["result"].clone())
    }

    fn args(a: &[u8], b: &[u8], c: &[u8], name: &str) -> Value {
        json!({"A": b64(a), "B": b64(b), "C": b64(c), "Name": name})
    }
}

impl Backend for Remote {
    async fn new_keypair(&self) -> Result<Keypair> {
        let r = self
            .call("NewKeypair", Self::args(&[], &[], &[], ""))
            .await?;
        let k = &r["Keypair"];
        Ok(Keypair {
            write_cap: bytes(&k["WriteCap"]).into(),
            read_cap: bytes(&k["ReadCap"]).into(),
            first: bytes(&k["First"]),
        })
    }

    async fn write_box(&self, write_cap: &[u8], index: &[u8], plaintext: &[u8]) -> Result<()> {
        let r = self
            .call("WriteBox", Self::args(write_cap, index, plaintext, ""))
            .await?;
        if r["Exists"].as_bool() == Some(true) {
            return Err(Error::BoxAlreadyExists);
        }
        Ok(())
    }

    async fn read_box(&self, read_cap: &[u8], index: &[u8]) -> Result<Read> {
        let r = self
            .call("ReadBox", Self::args(read_cap, index, &[], ""))
            .await?;
        Ok(match r["Read"]["Kind"].as_u64() {
            Some(0) => Read::Data(bytes(&r["Read"]["Plaintext"])),
            Some(2) => Read::Tombstone,
            _ => Read::NotFound,
        })
    }

    async fn replica_epoch(&self) -> Result<u64> {
        Ok(self
            .call("ReplicaEpoch", Self::args(&[], &[], &[], ""))
            .await?["N"]
            .as_u64()
            .unwrap_or(0))
    }

    async fn max_plaintext(&self) -> Result<usize> {
        Ok(self
            .call("MaxPlaintext", Self::args(&[], &[], &[], ""))
            .await?["N"]
            .as_u64()
            .unwrap_or(0) as usize)
    }

    async fn voucher_mint(&self, write_cap: &[u8], name: &str) -> Result<Minted> {
        let r = self
            .call("VoucherMint", Self::args(write_cap, &[], &[], name))
            .await?;
        let m = &r["Minted"];
        Ok(Minted {
            voucher: bytes(&m["Voucher"]).into(),
            payload: bytes(&m["Payload"]).into(),
            write_cap: bytes(&m["WriteCap"]).into(),
            read_cap: bytes(&m["ReadCap"]).into(),
            secret_key: bytes(&m["SecretKey"]).into(),
        })
    }

    async fn voucher_derive_stream(&self, voucher: &[u8]) -> Result<(Secret, Secret)> {
        let r = self
            .call("VoucherDeriveStream", Self::args(voucher, &[], &[], ""))
            .await?;
        Ok((bytes(&r["A"]).into(), bytes(&r["B"]).into()))
    }

    async fn voucher_induct(
        &self,
        voucher: &[u8],
        payload: &[u8],
        who_reply: &[u8],
    ) -> Result<Inducted> {
        let r = self
            .call("VoucherInduct", Self::args(voucher, payload, who_reply, ""))
            .await?;
        let i = &r["Induct"];
        Ok(Inducted {
            name: i["Name"].as_str().unwrap_or("").into(),
            mutated_read_cap: bytes(&i["MutatedReadCap"]).into(),
            sealed_reply: bytes(&i["SealedReply"]),
        })
    }

    async fn voucher_open(
        &self,
        secret_key: &[u8],
        sealed_reply: &[u8],
        write_cap: &[u8],
    ) -> Result<Opened> {
        let r = self
            .call(
                "VoucherOpen",
                Self::args(secret_key, sealed_reply, write_cap, ""),
            )
            .await?;
        let o = &r["Opened"];
        Ok(Opened {
            who_reply: bytes(&o["WhoReply"]).into(),
            mutated_write_cap: bytes(&o["MutatedWriteCap"]).into(),
        })
    }
}
