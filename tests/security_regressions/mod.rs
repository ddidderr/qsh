//! Cross-component regressions for request and session admission boundaries.

use super::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn expect_request_limit_refusal(recv: &mut quinn::RecvStream) {
    let error = tokio::time::timeout(Duration::from_secs(3), qsh::proto::read_frame(recv))
        .await
        .expect("invalid request did not receive a prompt refusal")
        .unwrap()
        .expect("server closed without a refusal");
    let qsh::proto::Frame::Error(message) = error else {
        panic!("expected refusal diagnostic, got {error:?}");
    };
    assert!(
        message.contains("invalid qsh/1 session request"),
        "{message}"
    );
    assert!(
        message.contains(&format!("{} request bytes", qsh::proto::MAX_REQUEST)),
        "{message}"
    );
    let exit = qsh::proto::read_frame(recv).await.unwrap().unwrap();
    assert!(
        matches!(exit, qsh::proto::Frame::Exit(status) if status.wait_status() == 126),
        "unexpected refusal status: {exit:?}"
    );
}

#[test]
fn legacy_v1_limit_refusals_leave_the_connection_usable() {
    let fixture = Fixture::start(&["--no-shell", "--command", "true"]);
    runtime().block_on(async {
        let conn = raw_connect(&fixture.client_dir, fixture.port).await;
        let mut arguments = vec![String::new(); qsh::proto::MAX_ARGS + 1];
        arguments[0] = "true".into();
        let request = qsh::proto::Request {
            version: qsh::proto::PROTOCOL_VERSION,
            user: None,
            command: Some(arguments),
            pty: None,
            env: Vec::new(),
        };
        // Bypass the safe writer as an untrusted peer can. The encoded bytes
        // fit easily; the decoded argument count must independently fail.
        let payload = postcard::to_stdvec(&request).unwrap();
        assert!(payload.len() < qsh::proto::MAX_REQUEST);
        let mut frame = vec![1];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&payload);
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&frame).await.unwrap();
        expect_request_limit_refusal(&mut recv).await;
        assert_eq!(raw_session(&conn, &["true"]).await, Some(0));

        // Model the baseline writer, which sends the complete formerly valid
        // request before it starts reading the server's reply.
        let request = qsh::proto::Request {
            version: qsh::proto::PROTOCOL_VERSION,
            user: Some("u".repeat(qsh::proto::MAX_REQUEST + 1)),
            command: Some(vec!["true".into()]),
            pty: None,
            env: Vec::new(),
        };
        let payload = postcard::to_stdvec(&request).unwrap();
        assert!(payload.len() > qsh::proto::MAX_REQUEST);
        assert!(payload.len() < qsh::proto::MAX_FRAME);
        let mut frame = vec![1];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&payload);
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), send.write_all(&frame))
            .await
            .expect("baseline request writer blocked before reading the refusal")
            .unwrap();
        expect_request_limit_refusal(&mut recv).await;
        assert_eq!(raw_session(&conn, &["true"]).await, Some(0));

        // A baseline qsh/1 peer can advertise the old one-MiB frame ceiling.
        // Reject the new request ceiling from the header without waiting for or
        // allocating its body, but still explain the rolling-upgrade failure.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut header = vec![1];
        header.extend_from_slice(
            &u32::try_from(qsh::proto::MAX_REQUEST + 1)
                .unwrap()
                .to_be_bytes(),
        );
        send.write_all(&header).await.unwrap();
        expect_request_limit_refusal(&mut recv).await;
        assert_eq!(raw_session(&conn, &["true"]).await, Some(0));
    });
}

#[test]
fn reconnects_cannot_reuse_sessions_that_are_still_being_reaped() {
    const SESSIONS_PER_KEY: usize = 32;
    let fixture = Fixture::start(&[]);
    runtime().block_on(async {
        let mut connections = Vec::new();
        let mut streams = Vec::new();
        for _ in 0..4 {
            let conn = raw_connect(&fixture.client_dir, fixture.port).await;
            for _ in 0..8 {
                let (send, mut recv) = raw_request(&conn, &["sleep", "30"], false).await.unwrap();
                wait_for_started(&mut recv).await;
                streams.push((send, recv));
            }
            connections.push(conn);
        }
        assert_eq!(streams.len(), SESSIONS_PER_KEY);
        let next = raw_connect(&fixture.client_dir, fixture.port).await;
        assert_ne!(raw_session(&next, &["true"]).await, Some(0));
        for conn in &connections {
            conn.close(0u32.into(), b"disconnect during running session");
        }
        // Closure returns connection slots quickly, but process groups retain
        // their session budget through HUP/TERM grace and final reaping.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_ne!(raw_session(&next, &["true"]).await, Some(0));
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if raw_session(&next, &["true"]).await == Some(0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("completed teardown did not return session permits");
        drop(streams);
    });
}

#[test]
fn local_escape_restores_the_terminal_without_waiting_for_the_remote_job() {
    let fixture = Fixture::start(&[]);
    let marker = fixture.tmp.path().join("escape-ready");
    let mut client = PtyClient::start(&fixture);
    let deadline = Instant::now() + Duration::from_secs(10);
    while client
        .termios()
        .local_flags
        .contains(nix::sys::termios::LocalFlags::ICANON)
    {
        assert!(Instant::now() < deadline, "client never entered raw mode");
        std::thread::sleep(Duration::from_millis(25));
    }
    client.write_line(&format!(
        "trap '' HUP; echo $$ > {}; sleep 30",
        marker.display()
    ));
    while !marker.exists() {
        assert!(Instant::now() < deadline, "remote job did not start");
        std::thread::sleep(Duration::from_millis(25));
    }
    let pid = wait_for_pid(&marker);
    client.write_line("~.");
    let status = client.wait_status(Duration::from_secs(2));
    assert_eq!(status, Some(255), "escape waited for the remote job");
    assert!(client
        .termios()
        .local_flags
        .contains(nix::sys::termios::LocalFlags::ICANON));
    assert!(client
        .termios()
        .local_flags
        .contains(nix::sys::termios::LocalFlags::ECHO));
    client.finish();
    let deadline = Instant::now() + Duration::from_secs(10);
    while process_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "server did not clean up the escaped session"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
