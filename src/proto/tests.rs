use super::*;

fn request() -> Request {
    Request {
        version: PROTOCOL_VERSION,
        user: None,
        command: Some(vec![
            "rsync".into(),
            "--server".into(),
            ".".into(),
            "/backup".into(),
        ]),
        pty: None,
        env: Vec::new(),
    }
}

/// Deliberately bypass `write_frame`'s checks to model an untrusted peer.
fn wire_frame(kind: u8, payload: &[u8]) -> std::io::Cursor<Vec<u8>> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    std::io::Cursor::new(bytes)
}

fn wire_header(kind: u8, length: usize) -> std::io::Cursor<Vec<u8>> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&(length as u32).to_be_bytes());
    std::io::Cursor::new(bytes)
}

async fn roundtrip(frame: Frame) -> Frame {
    let mut buf = Vec::new();
    write_frame(&mut buf, &frame).await.unwrap();
    let mut cursor = std::io::Cursor::new(buf);
    read_frame(&mut cursor).await.unwrap().unwrap()
}

#[tokio::test]
async fn binary_data_survives_untouched() {
    // Everything a naive line-oriented transport would mangle.
    let payload: Vec<u8> = (0u8..=255).chain([b'\r', b'\n', 0]).collect();
    match roundtrip(Frame::Stdout(payload.clone())).await {
        Frame::Stdout(got) => assert_eq!(got, payload),
        other => panic!("wrong frame: {other:?}"),
    }
}

#[tokio::test]
async fn raw_payloads_keep_the_wire_format_and_size_limit() {
    for (tag, frame, payload) in [
        (kind::STDIN, Frame::Stdin(vec![0, 255]), vec![0, 255]),
        (kind::STDOUT, Frame::Stdout(vec![0, 255]), vec![0, 255]),
        (kind::STDERR, Frame::Stderr(vec![0, 255]), vec![0, 255]),
        (kind::SIGNAL, Frame::Signal("INT".into()), b"INT".to_vec()),
        (kind::ERROR, Frame::Error("oops".into()), b"oops".to_vec()),
        (kind::STARTED, Frame::Started, Vec::new()),
        (kind::STDIN_EOF, Frame::StdinEof, Vec::new()),
    ] {
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &frame).await.unwrap();
        let mut expected = vec![tag];
        expected.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        expected.extend_from_slice(&payload);
        assert_eq!(encoded, expected);
    }
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &Frame::Stdout(vec![0; MAX_FRAME]))
        .await
        .unwrap();
    assert_eq!(encoded.len(), MAX_FRAME + 5);
    for frame in [
        Frame::Stdin(vec![0; MAX_FRAME + 1]),
        Frame::Stdout(vec![0; MAX_FRAME + 1]),
        Frame::Stderr(vec![0; MAX_FRAME + 1]),
        Frame::Error("x".repeat(MAX_FRAME + 1)),
    ] {
        let mut encoded = Vec::new();
        assert!(write_frame(&mut encoded, &frame).await.is_err());
        assert!(encoded.is_empty());
    }
}

#[tokio::test]
async fn request_roundtrips() {
    let req = Request {
        version: PROTOCOL_VERSION,
        user: Some("alice".into()),
        command: Some(vec![
            "rsync".into(),
            "--server".into(),
            "-vlogDtpre.iLsfxC".into(),
        ]),
        pty: None,
        env: vec![("LANG".into(), "C.UTF-8".into())],
    };
    match roundtrip(Frame::Request(req)).await {
        Frame::Request(got) => {
            assert_eq!(got.user.as_deref(), Some("alice"));
            assert_eq!(got.command.unwrap()[2], "-vlogDtpre.iLsfxC");
            assert!(got.pty.is_none());
        }
        other => panic!("wrong frame: {other:?}"),
    }
}

#[tokio::test]
async fn request_reader_accepts_rsync_and_field_boundaries() {
    let mut req = request();
    let args = req.command.as_mut().unwrap();
    args.resize(MAX_ARGS, "path".into());
    args[3] = "x".repeat(MAX_VALUE_BYTES);
    req.user = Some("u".repeat(MAX_NAME_BYTES));
    req.pty = Some(PtyRequest {
        term: "t".repeat(MAX_NAME_BYTES),
        size: PtySize::default(),
    });
    req.env = vec![("NAME".into(), "value".into()); MAX_ENV];
    req.env[0] = ("E".repeat(MAX_NAME_BYTES), "v".repeat(MAX_VALUE_BYTES));
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &Frame::Request(req)).await.unwrap();
    assert!(bytes.len() < MAX_REQUEST);
    let got = read_request(&mut std::io::Cursor::new(bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.command.as_ref().unwrap().len(), MAX_ARGS);
    assert_eq!(got.command.as_ref().unwrap()[0], "rsync");
    assert_eq!(got.env.len(), MAX_ENV);
    assert_eq!(got.env[0].1.len(), MAX_VALUE_BYTES);
}

#[tokio::test]
async fn dense_argument_and_environment_lists_are_rejected() {
    for req in [
        Request {
            command: Some(vec![String::new(); MAX_ARGS + 1]),
            ..request()
        },
        Request {
            env: vec![(String::new(), String::new()); MAX_ENV + 1],
            ..request()
        },
    ] {
        let payload = postcard::to_stdvec(&req).unwrap();
        assert!(payload.len() < MAX_REQUEST);
        let error = read_request(&mut wire_frame(kind::REQUEST, &payload))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut outgoing = Vec::new();
        assert!(write_frame(&mut outgoing, &Frame::Request(req))
            .await
            .is_err());
        assert!(outgoing.is_empty());
    }
}

#[tokio::test]
async fn untrusted_sequence_length_cannot_drive_capacity() {
    // Version, absent user, present command, then an impossible count.
    // Postcard has no size hint when that count exceeds the bytes left.
    let mut payload = vec![PROTOCOL_VERSION as u8, 0, 1];
    payload.extend(postcard::to_stdvec(&usize::MAX).unwrap());
    let error = read_request(&mut wire_frame(kind::REQUEST, &payload))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn every_request_string_is_bounded_on_read_and_write() {
    for req in [
        Request {
            user: Some("x".repeat(MAX_NAME_BYTES + 1)),
            ..request()
        },
        Request {
            command: Some(vec!["x".repeat(MAX_VALUE_BYTES + 1)]),
            ..request()
        },
        Request {
            pty: Some(PtyRequest {
                term: "x".repeat(MAX_NAME_BYTES + 1),
                size: PtySize::default(),
            }),
            ..request()
        },
        Request {
            env: vec![("x".repeat(MAX_NAME_BYTES + 1), String::new())],
            ..request()
        },
        Request {
            env: vec![("LANG".into(), "x".repeat(MAX_VALUE_BYTES + 1))],
            ..request()
        },
    ] {
        let payload = postcard::to_stdvec(&req).unwrap();
        let error = read_request(&mut wire_frame(kind::REQUEST, &payload))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut outgoing = Vec::new();
        assert!(write_frame(&mut outgoing, &Frame::Request(req))
            .await
            .is_err());
        assert!(outgoing.is_empty());
    }
}

#[tokio::test]
async fn aggregate_request_budget_is_enforced_on_read_and_write() {
    let req = Request {
        command: Some(vec!["x".repeat(MAX_VALUE_BYTES); 4]),
        ..request()
    };
    let payload = postcard::to_stdvec(&req).unwrap();
    assert!(payload.len() > MAX_REQUEST);
    let error = read_request(&mut wire_header(kind::REQUEST, payload.len()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let mut outgoing = Vec::new();
    assert!(write_frame(&mut outgoing, &Frame::Request(req))
        .await
        .is_err());
    assert!(outgoing.is_empty());
}

#[tokio::test]
async fn request_header_is_checked_without_reading_a_body() {
    for (kind, length) in [
        (kind::STDIN, MAX_FRAME),
        (kind::STDOUT, MAX_FRAME),
        (kind::ERROR, 4096),
        (kind::REQUEST, MAX_REQUEST + 1),
        (255, MAX_FRAME),
    ] {
        let mut header = wire_header(kind, length);
        let error = read_request(&mut header).await.unwrap_err();
        // UnexpectedEof would mean the reader attempted to read a body.
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(header.position(), 5);
    }
}

#[tokio::test]
async fn each_control_frame_has_its_own_header_budget() {
    for (kind, limit) in [
        (kind::REQUEST, MAX_REQUEST),
        (kind::STARTED, 0),
        (kind::STDIN_EOF, 0),
        (kind::RESIZE, 6),
        (kind::EXIT, 11),
        (kind::SIGNAL, 16),
        (kind::ERROR, 4096),
    ] {
        let error = read_frame(&mut wire_header(kind, limit + 1))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn structured_frames_reject_trailing_payload_bytes() {
    for (kind, mut payload) in [
        (kind::REQUEST, postcard::to_stdvec(&request()).unwrap()),
        (
            kind::RESIZE,
            postcard::to_stdvec(&PtySize::default()).unwrap(),
        ),
        (
            kind::EXIT,
            postcard::to_stdvec(&ExitStatus {
                code: 0,
                signal: None,
            })
            .unwrap(),
        ),
    ] {
        payload.push(0);
        let error = read_frame(&mut wire_frame(kind, &payload))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn numeric_control_limits_cover_largest_varints() {
    let size = PtySize {
        cols: u16::MAX,
        rows: u16::MAX,
    };
    match roundtrip(Frame::Resize(size)).await {
        Frame::Resize(got) => assert_eq!(got, size),
        other => panic!("wrong frame: {other:?}"),
    }
    match roundtrip(Frame::Exit(ExitStatus {
        code: i32::MIN,
        signal: Some(i32::MIN),
    }))
    .await
    {
        Frame::Exit(got) => {
            assert_eq!(got.code, i32::MIN);
            assert_eq!(got.signal, Some(i32::MIN));
        }
        other => panic!("wrong frame: {other:?}"),
    }
}

#[tokio::test]
async fn exit_status_roundtrips() {
    match roundtrip(Frame::Exit(ExitStatus {
        code: 0,
        signal: Some(libc::SIGINT),
    }))
    .await
    {
        Frame::Exit(s) => assert_eq!(s.wait_status(), 130),
        other => panic!("wrong frame: {other:?}"),
    }
}

#[tokio::test]
async fn clean_eof_is_none() {
    let mut empty = std::io::Cursor::new(Vec::new());
    assert!(read_frame(&mut empty).await.unwrap().is_none());
    assert!(read_request(&mut empty).await.unwrap().is_none());
}

#[tokio::test]
async fn truncated_headers_and_bodies_are_errors() {
    let bytes = wire_header(kind::STDIN, 1).into_inner();
    for length in 1..=bytes.len() {
        let mut truncated = std::io::Cursor::new(bytes[..length].to_vec());
        let error = read_frame(&mut truncated).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}

#[tokio::test]
async fn oversized_frame_is_rejected() {
    let mut buf = Vec::new();
    buf.push(kind::STDOUT);
    buf.extend_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
    let mut cursor = std::io::Cursor::new(buf);
    assert!(read_frame(&mut cursor).await.is_err());
}

#[test]
fn signal_names_parse_with_and_without_prefix() {
    assert_eq!(signal_number("INT"), Some(libc::SIGINT));
    assert_eq!(signal_number("SIGTERM"), Some(libc::SIGTERM));
    assert_eq!(signal_number("nope"), None);
}
