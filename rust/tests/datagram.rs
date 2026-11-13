#![cfg(feature = "std")]

use std::sync::Arc;
use std::time::Duration;

use pigeonhole_protocols::protocols::datagram::{QUEUE, Tunnel};
use pigeonhole_protocols::protocols::stream::{self, Tuning};
use pigeonhole_protocols::transport::sim::World;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;

fn tuning() -> Tuning {
    Tuning { window: 4, reads: 6, flush: Duration::from_millis(2), poll_min: Duration::from_millis(1), poll_max: Duration::from_millis(20), hot: Duration::from_millis(5) }
}

async fn udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn echo_keeps_datagram_boundaries() {
    let w = Arc::new(World::default());
    w.state().max_plaintext = 64;
    let (mut a, mut b) = stream::new_link(&*w).await.unwrap();
    let echo = udp().await;
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    let client = Tunnel::new(udp().await, None);
    let server = Tunnel::new(udp().await, Some(echo_addr));
    let app = udp().await;
    app.connect(client.local_addr().unwrap()).await.unwrap();
    let t = tuning();
    let drive = async {
        let mut buf = vec![0u8; 65536];
        // Records span boxes of 63 bytes.
        for n in [1, 61, 62, 300, 1400, 5] {
            let d: Vec<u8> = (0..n).map(|i| i as u8).collect();
            app.send(&d).await.unwrap();
            let m = timeout(Duration::from_secs(5), app.recv(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..m], &d[..]);
        }
        client.close();
    };
    let (_, rc, rs) = tokio::join!(drive, client.run(w.clone(), &mut a, &t, None, None), async {
        let first = stream::accept(&*w, &b, &t).await.unwrap();
        server.run(w.clone(), &mut b, &t, Some(first), None).await
    });
    rc.unwrap();
    rs.unwrap();
    assert_eq!(a.write_index, b.read_index);
    assert_eq!(b.write_index, a.read_index);
}

#[tokio::test]
async fn behind_drops_the_oldest_and_taps_the_first() {
    let w = Arc::new(World::default());
    let (mut a, mut b) = stream::new_link(&*w).await.unwrap();
    let sink = udp().await;
    let client = Tunnel::new(udp().await, None);
    let server = Tunnel::new(udp().await, Some(sink.local_addr().unwrap()));
    for k in 0..20u8 {
        client.push(vec![k]);
    }
    client.close();
    client.push(vec![99]);
    let (tx, rx) = oneshot::channel();
    let t = tuning();
    let (rc, rs) = tokio::join!(client.run(w.clone(), &mut a, &t, None, None), server.run(w.clone(), &mut b, &t, None, Some(tx)));
    rc.unwrap();
    rs.unwrap();
    let kept = 20 - QUEUE as u8;
    assert_eq!(rx.await.unwrap(), vec![kept]);
    let mut buf = [0u8; 16];
    for k in kept + 1..20 {
        let n = timeout(Duration::from_secs(1), sink.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], &[k]);
    }
    assert!(timeout(Duration::from_millis(100), sink.recv(&mut buf)).await.is_err());
}
