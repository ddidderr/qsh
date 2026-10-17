"""Interactive sessions: a real terminal from the test host to qsh.

`docker exec -it` gives the client process a terminal inside its container
and forwards the size of ours to it. Driving that from pexpect makes the
whole chain real: a resize here becomes SIGWINCH for `docker`, a resize of
the container's terminal, SIGWINCH for `qsh`, a Resize frame, and finally
TIOCSWINSZ on the server's PTY.
"""

from __future__ import annotations

import re

import pexpect

from .qsh import QshClient

# A prompt no login script will print by accident, set once the shell runs.
PROMPT = "QSH-E2E-PROMPT$ "
PROMPT_RE = re.escape(PROMPT)


class Terminal:
    """A pexpect-driven `qsh` with a terminal on both ends."""

    def __init__(
        self,
        client: QshClient,
        host: str,
        *command: str,
        options: tuple[str, ...] = (),
        rows: int = 24,
        cols: int = 200,
        timeout: float = 20,
        env: dict[str, str] | None = None,
    ) -> None:
        argv = client.argv(host, *command, options=options)
        self.node, self.user, self.argv = client.node, client.user, argv
        env = {"TERM": "xterm-256color", **(env or {})}
        cmd = client.node.exec_argv(argv, user=client.user, env=env, interactive=True, tty=True)
        self.child = pexpect.spawn(
            cmd[0], cmd[1:], dimensions=(rows, cols), timeout=timeout, encoding="utf-8", codec_errors="replace"
        )
        self.transcript: list[str] = []

    # ------------------------------------------------------------ io

    def expect(self, pattern, timeout: float | None = None) -> str:
        """Wait for `pattern` (regex or list); return everything up to it."""
        try:
            self.child.expect(pattern, timeout=timeout)
        except (pexpect.TIMEOUT, pexpect.EOF) as exc:
            seen = (self.child.before or "")[-2000:]
            raise AssertionError(f"waiting for {pattern!r}: {type(exc).__name__}; last output:\n{seen}") from None
        before = self.child.before or ""
        self.transcript.append(before + (self.child.after if isinstance(self.child.after, str) else ""))
        return before

    def send(self, text: str) -> None:
        self.child.send(text)

    def sendline(self, text: str = "") -> None:
        # A terminal sends CR for Enter; the remote line discipline maps it.
        self.child.send(text + "\r")

    def sendcontrol(self, char: str) -> None:
        self.child.sendcontrol(char)

    # ------------------------------------------------------------ shell helpers

    def set_prompt(self) -> None:
        """Replace whatever prompt the login shell set with a known one.

        Bracketed paste is switched off too: its mode switches would otherwise
        surround every command's output.
        """
        self.sendline(f"bind 'set enable-bracketed-paste off'; export PS1='{PROMPT}' PROMPT_COMMAND=''")
        self.expect(PROMPT_RE)
        # The echoed command line itself contained the prompt text once.
        self.sendline("")
        self.expect(PROMPT_RE)

    def command(self, line: str, timeout: float | None = None) -> str:
        """Run one shell command and return its output, without the echo."""
        marker = "QSH-E2E-END"
        self.sendline(f"{line}; echo {marker}-$?")
        self.expect(re.escape(line) + r"[^\n]*\n", timeout=timeout)
        output = self.expect(marker + r"-(\d+)", timeout=timeout)
        self.status = int(self.child.match.group(1))
        self.expect(PROMPT_RE, timeout=timeout)
        return output.replace("\r\n", "\n")

    def resize(self, rows: int, cols: int) -> None:
        self.child.setwinsize(rows, cols)

    # ------------------------------------------------------------ teardown

    def wait_exit(self, timeout: float = 20) -> int:
        """Wait for qsh to exit and return its status."""
        try:
            self.child.expect(pexpect.EOF, timeout=timeout)
        except pexpect.TIMEOUT:
            raise AssertionError(f"qsh did not exit within {timeout}s; last output:\n{(self.child.before or '')[-2000:]}") from None
        self.child.close()
        if self.child.signalstatus is not None:
            return 128 + self.child.signalstatus
        return self.child.exitstatus

    def close(self) -> None:
        """End the session for good, including the qsh inside the container.

        Killing the local `docker exec` alone would leave that qsh, and its
        remote shell, running on as a session no scenario owns.
        """
        if self.child.isalive():
            try:
                self.child.send("\r~.")
                self.child.expect(pexpect.EOF, timeout=5)
            except (pexpect.TIMEOUT, pexpect.EOF, OSError):
                pass
            self.child.terminate(force=True)
        self.node.kill_command(self.user, self.argv)
