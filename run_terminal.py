#!/usr/bin/env python3
"""Bound an interactive in-process Claude team to ten minutes (POSIX)."""
import argparse
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import sys
import termios
import time
import tty


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('trial', type=Path)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--model')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 600:
        parser.error('Time limit must be 1..600 seconds')
    binary = os.environ.get('CLAUDE_BIN') or shutil.which('claude')
    if not binary:
        candidates = sorted((Path.home() / 'Library/Application Support/Claude/claude-code').glob('**/claude.app/Contents/MacOS/claude'))
        if candidates:
            binary = str(candidates[-1])
    if not binary:
        parser.error('Claude Code CLI not found; no model call has been made')
    if not sys.stdin.isatty():
        parser.error('Run this launcher from an interactive terminal')
    trial = args.trial.resolve()
    if (trial / 'evidence/terminal.log').exists():
        parser.error('Use a fresh trial; terminal.log already exists')
    prompt = (trial / 'PROMPT.txt').read_text()
    old = termios.tcgetattr(sys.stdin)
    started = time.monotonic()
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(trial)
        os.environ['CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS'] = '1'
        os.environ['CLAUDE_CODE_ENABLE_TODO_TOOLS'] = '1'
        command = [binary, '--teammate-mode', 'in-process']
        if args.model:
            command += ['--model', args.model]
        command.append(prompt)
        os.execv(binary, command)
    timed_out = False
    def stop_group(sig):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        tty.setraw(sys.stdin)
        with (trial / 'evidence/terminal.log').open('xb') as log:
            while True:
                if time.monotonic() - started >= args.seconds:
                    timed_out = True
                    break
                ready, _, _ = select.select([master, sys.stdin], [], [], 0.2)
                if master in ready:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    log.write(data)
                    log.flush()
                    os.write(sys.stdout.fileno(), data)
                if sys.stdin in ready:
                    data = os.read(sys.stdin.fileno(), 65536)
                    if not data:
                        break
                    os.write(master, data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        stop_group(signal.SIGTERM)
        time.sleep(0.3)
        stop_group(signal.SIGKILL)
        os.close(master)
        _, status = os.waitpid(pid, 0)
        (trial / 'evidence/launcher.json').write_text(json.dumps({
            'timed_out': timed_out, 'elapsed_seconds': time.monotonic() - started,
            'wait_status': status, 'cli_path': binary,
            'requested_model': args.model,
            'note': 'Terminal exit or timeout is not a scientific outcome.'}, indent=2))


if __name__ == '__main__':
    main()
