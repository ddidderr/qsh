//! Cross-component regressions for request and session admission boundaries.

use super::*;
use std::os::fd::AsRawFd;

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

/// A mounted filesystem that never answers a single request. Every lookup
/// under it blocks in the kernel until the connection is aborted, which is
/// what an authorized client can arrange for a program of its own (FUSE
/// mounts are unprivileged on Linux, and a stalled network filesystem does
/// the same).
struct HangingMount {
    dir: PathBuf,
    /// Kept open for the lifetime of the mount; closing it alone would not
    /// release the pending requests.
    _fuse: std::fs::File,
    /// Requests already waiting before anything touched the mount: the
    /// kernel counts its own INIT request, which nobody answers either.
    baseline: u64,
    /// Last, so it is released only once the mount is gone.
    _fusectl: Fusectl,
}

impl HangingMount {
    /// `None` where this machine cannot mount one: not root, or no FUSE.
    #[allow(
        unsafe_code,
        reason = "mount(2) has no safe wrapper in the enabled nix features"
    )]
    fn new(dir: PathBuf) -> Option<Self> {
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping: not running as root, cannot mount a filesystem");
            return None;
        }
        let fuse = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .map_err(|error| eprintln!("skipping: cannot open /dev/fuse: {error}"))
            .ok()?;
        // `fusectl` is how a stuck request is observed and released.
        let fusectl = Fusectl::acquire().or_else(|| {
            eprintln!("skipping: {FUSE_CONNECTIONS} is not available");
            None
        })?;
        std::fs::create_dir_all(&dir)
            .map_err(|error| eprintln!("skipping: cannot create {}: {error}", dir.display()))
            .ok()?;
        let target = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let options = std::ffi::CString::new(format!(
            "fd={},rootmode=40755,user_id=0,group_id=0",
            fuse.as_raw_fd()
        ))
        .unwrap();
        let source = std::ffi::CString::new("qsh-hangfs").unwrap();
        let fstype = std::ffi::CString::new("fuse").unwrap();
        // SAFETY: four NUL-terminated strings and no flags; the descriptor in
        // `options` stays open for as long as the mount does.
        let mounted = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                0,
                options.as_ptr().cast(),
            )
        };
        if mounted != 0 {
            eprintln!(
                "skipping: cannot mount a FUSE filesystem: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }
        let mut mount = Self {
            dir,
            _fuse: fuse,
            baseline: 0,
            _fusectl: fusectl,
        };
        mount.baseline = mount.waiting();
        Some(mount)
    }

    /// A path under the mount. Executing it blocks in `execve` forever.
    fn program(&self) -> PathBuf {
        self.dir.join("program")
    }

    /// The kernel's connection directory, found through `mountinfo` because
    /// stat'ing the mount point would itself block.
    fn connection(&self) -> Option<PathBuf> {
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let point = self.dir.to_str()?;
        for line in mounts.lines() {
            let mut fields = line.split_whitespace();
            let device = fields.nth(2)?;
            if fields.nth(1) == Some(point) {
                let minor = device.split(':').nth(1)?;
                return Some(PathBuf::from(FUSE_CONNECTIONS).join(minor));
            }
        }
        None
    }

    /// How many requests the kernel is holding for a filesystem that never
    /// answers: the test's proof that a session really is stuck in `execve`.
    fn waiting(&self) -> u64 {
        self.connection()
            .and_then(|dir| std::fs::read_to_string(dir.join("waiting")).ok())
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }

    fn wait_for_a_stuck_request(&self, stage: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.waiting() <= self.baseline {
            assert!(Instant::now() < deadline, "no request ever stuck: {stage}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for HangingMount {
    #[allow(unsafe_code, reason = "umount2(2) has no safe wrapper here")]
    fn drop(&mut self) {
        // Abort first: a pending request outlives the unmount otherwise, and
        // with it the server's stuck spawn.
        if let Some(connection) = self.connection() {
            let _ = std::fs::write(connection.join("abort"), "1");
        }
        let target = std::ffi::CString::new(self.dir.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path; a lazy unmount cannot block.
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    }
}

const FUSE_CONNECTIONS: &str = "/sys/fs/fuse/connections";

/// Every `HangingMount` shares the host's `fusectl` mount. One at a time, so
/// the test that mounted it cannot take it away while another still reads it.
static FUSECTL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The lock over `fusectl`, and the mount itself if this test made it.
/// Unmounted again on every way out; a host's own mount is left alone.
struct Fusectl {
    mounted: bool,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Fusectl {
    fn acquire() -> Option<Self> {
        // A failed FUSE test must not fail every later one.
        let lock = FUSECTL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fusectl = Self {
            mounted: !fusectl_mounted() && mount_fusectl(),
            _lock: lock,
        };
        fusectl_mounted().then_some(fusectl)
    }
}

impl Drop for Fusectl {
    #[allow(unsafe_code, reason = "umount2(2) has no safe wrapper here")]
    fn drop(&mut self) {
        if self.mounted {
            let target = std::ffi::CString::new(FUSE_CONNECTIONS).unwrap();
            // SAFETY: a NUL-terminated path; a lazy unmount cannot block.
            unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
        }
    }
}

/// Setting up a `HangingMount` can fail after `fusectl` was mounted for it.
#[test]
fn a_failed_hanging_mount_leaves_fusectl_as_it_found_it() {
    let Some(first) = Fusectl::acquire() else {
        return;
    };
    let ours = first.mounted;
    drop(first);

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("file"), "").unwrap();
    assert!(HangingMount::new(tmp.path().join("file/hang")).is_none());

    let after = Fusectl::acquire().expect("fusectl could not be mounted again");
    assert_eq!(after.mounted, ours, "a failed setup left fusectl changed");
}

fn fusectl_mounted() -> bool {
    std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|mounts| {
        mounts
            .lines()
            .any(|line| line.split_whitespace().nth(4) == Some(FUSE_CONNECTIONS))
    })
}

#[allow(unsafe_code, reason = "mount(2) has no safe wrapper here")]
fn mount_fusectl() -> bool {
    let source = std::ffi::CString::new("fusectl").unwrap();
    let target = std::ffi::CString::new(FUSE_CONNECTIONS).unwrap();
    let fstype = std::ffi::CString::new("fusectl").unwrap();
    // SAFETY: three NUL-terminated strings, no flags and no options.
    let mounted = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    mounted == 0
}

/// An authorized client names the program it wants to run, so it chooses how
/// long `execve` takes. Running the spawn on a Tokio worker let one client
/// stall every other session on the server (threat model, actor 3: "It cannot
/// crash the server or block its async workers").
#[test]
fn a_session_stuck_in_exec_does_not_stall_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    // One worker, so a single stuck spawn is the whole runtime.
    let fixture = Fixture::start_with_env(&[], &[("TOKIO_WORKER_THREADS", "1")]);
    let Some(mount) = HangingMount::new(tmp.path().join("hang")) else {
        return;
    };

    let mut stuck = fixture
        .client()
        .arg(mount.program())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the client whose program hangs");
    mount.wait_for_a_stuck_request("the session that runs a program on a hanging filesystem");

    let (code, out, err) = fixture.exec(&["/bin/echo", "alive"]);
    assert_eq!(code, 0, "an ordinary session was refused: {err}");
    assert_eq!(out.trim_end(), "alive", "{err}");

    let _ = stuck.kill();
    let _ = stuck.wait();
}

/// A forked child holds a copy of every descriptor the server has open until
/// it execs. One stuck in `execve` used to keep other sessions' pipes open
/// with it, so those sessions never saw end of file and never ended (threat
/// model, actor 3: "It cannot degrade other keys beyond the per-key limits").
#[test]
fn a_session_stuck_in_exec_does_not_hold_other_sessions_open() {
    use std::io::{BufRead, Write};

    let tmp = tempfile::tempdir().unwrap();
    let fixture = Fixture::start(&[]);
    let Some(mount) = HangingMount::new(tmp.path().join("hang")) else {
        return;
    };

    // A session that ends when its input does. Once it has echoed a line, the
    // server holds the write end of its stdin.
    let mut open = fixture
        .client()
        .arg("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the client that runs cat");
    let mut input = open.stdin.take().unwrap();
    let mut output = std::io::BufReader::new(open.stdout.take().unwrap());
    writeln!(input, "ready").unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");

    // Forked while that descriptor is open, so it starts with a copy of it.
    let mut stuck = fixture
        .client()
        .arg(mount.program())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the client whose program hangs");
    mount.wait_for_a_stuck_request("the session that runs a program on a hanging filesystem");

    drop(input);
    let status = wait_with_deadline_status(&mut open, Duration::from_secs(20));
    assert_eq!(
        status,
        Some(0),
        "closing its input did not end the session while another was stuck in exec"
    );

    let _ = stuck.kill();
    let _ = stuck.wait();
}

/// A child stuck in `execve` belongs to its session: when the client goes
/// away, the child must die before it can run anything (threat model, actor
/// 3: session cleanup on disconnect).
#[test]
fn a_session_stuck_in_exec_ends_with_its_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = Fixture::start(&[]);
    let Some(mount) = HangingMount::new(tmp.path().join("hang")) else {
        return;
    };

    runtime().block_on(async {
        let conn = raw_connect(&fixture.client_dir, fixture.port).await;
        let _streams = raw_request(&conn, &[mount.program().to_str().unwrap()], false)
            .await
            .expect("sending the request whose program hangs");
        mount.wait_for_a_stuck_request("the session that runs a program on a hanging filesystem");
        conn.close(0u32.into(), b"disconnect while exec is pending");

        // A killed waiter withdraws its unanswered request, so the count
        // drops while the filesystem still hangs: the child died before it
        // could run.
        let deadline = Instant::now() + Duration::from_secs(10);
        while mount.waiting() > mount.baseline {
            assert!(
                Instant::now() < deadline,
                "a child stuck in exec outlived its connection"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let (code, _, err) = fixture.exec(&["/bin/echo", "alive"]);
    assert_eq!(code, 0, "an ordinary session was refused: {err}");
}

/// A graceful stop drops every session, including one whose child is still
/// in `execve`; that child must not be left to run once the filesystem
/// answers.
#[test]
fn a_session_stuck_in_exec_dies_with_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::start(&[]);
    let Some(mount) = HangingMount::new(tmp.path().join("hang")) else {
        return;
    };

    let mut stuck = fixture
        .client()
        .arg(mount.program())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starting the client whose program hangs");
    mount.wait_for_a_stuck_request("the session that runs a program on a hanging filesystem");

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(fixture.server.id()).unwrap()),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while fixture.server.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the server did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while mount.waiting() > mount.baseline {
        assert!(
            Instant::now() < deadline,
            "a child stuck in exec outlived the server"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = stuck.kill();
    let _ = stuck.wait();
}
