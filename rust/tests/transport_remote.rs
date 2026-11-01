//! The Pigeonhole the Go module's pigeonhole-sim serves at $SIM_SOCKET, reached from Rust.

use pigeonhole_protocols::transport::remote::Remote;
use pigeonhole_protocols::transport::{Backend, Error, Read};

#[tokio::test]
async fn remote() {
    let Ok(sock) = std::env::var("SIM_SOCKET") else {
        return;
    };
    let r = Remote {
        socket: sock.into(),
    };
    let kp = r.new_keypair().await.unwrap();
    assert_eq!(
        (kp.write_cap.len(), kp.read_cap.len(), kp.first.len()),
        (168, 136, 104)
    );
    assert_eq!(
        r.read_box(&kp.read_cap, &kp.first).await,
        Ok(Read::NotFound)
    );
    r.write_box(&kp.write_cap, &kp.first, b"a").await.unwrap();
    assert_eq!(
        r.write_box(&kp.write_cap, &kp.first, b"b").await,
        Err(Error::BoxAlreadyExists)
    );
    assert_eq!(
        r.read_box(&kp.read_cap, &kp.first).await,
        Ok(Read::Data(b"a".to_vec()))
    );
    assert_eq!(r.max_plaintext().await, Ok(1530));
    let m = r.voucher_mint(&kp.write_cap, "x").await.unwrap();
    assert_eq!(
        r.voucher_derive_stream(&m.voucher).await.unwrap(),
        (m.write_cap, m.read_cap)
    );
}
