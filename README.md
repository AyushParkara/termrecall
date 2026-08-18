# TermRecall

TermRecall safely captures supported GNOME Terminal Bash sessions and offers recoverable tabs after same-boot loss, logout, or reboot. V1 targets Linux Mint 22.3 Cinnamon, GNOME Terminal, Bash, and Python 3.12.

## Safety and scope

Restoration is reconstruction, not process-memory continuation. TermRecall restores directories and can restart only separately selected and approved commands. It never automatically executes a stored command. Explicit Bash `exit` sessions are excluded; ambiguous GUI/signal/EOF loss remains eligible. Same-boot live or unknown process identities are excluded.

V1 does not restore scrollback, panes, window geometry/grouping, process memory, SSH sessions, arbitrary environments, other shells/terminals, tmux/Zellij, Windows, or macOS.

## Install for one user

From a verified source checkout, run the per-user POSIX bootstrap. It refuses root/sudo, checks `python3.12` with `venv`, a C11 compiler (`cc`), and Bash, then plans, builds, stages, and activates an isolated delegate without root privileges or system-wide install:

```bash
./install.sh --full
```

`--full` enables Bash, autostart, and chooser. Use `--no-autostart`, `--commands-only`, or `--upgrade`, or pass `--bash|--autostart|--chooser enable|disable|preserve`. Add `--dry-run` to render the plan with zero writes. Interactive mode (no mode flag) prompts for the three integration states. See [docs/INSTALL.md](docs/INSTALL.md) for prerequisites, modes, and the safety model. Do not install with root privileges.

After installation:

```bash
termrecall status
termrecall snapshot
termrecall list
termrecall restore
termrecall discard WORKSPACE_ID
termrecall doctor
termrecall chooser enable
```

Installed integrations can be reconfigured without reinstalling:

```bash
termrecall setup --bash enable --autostart disable --chooser preserve
termrecall autostart enable|disable
termrecall uninstall --yes                     # removes app + Bash + autostart; keeps chooser/state
termrecall uninstall --yes --purge-state        # also quarantines and deletes recovery state
```

The Bash hook is packaged at `termrecall/data/bash/termrecall.bash`; source it only from interactive Bash configuration. The Cinnamon autostart desktop file is packaged at `termrecall/data/xdg/termrecall.desktop` and starts one login coordinator.

## Development and release checks

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q -m 'not desktop'
.venv/bin/python -m compileall -q src tests
```

The desktop smoke test is opt-in and opens real GNOME Terminal windows only when `TERMRECALL_DESKTOP_TEST=1`. Release acceptance also requires the manual Linux Mint procedure in [docs/acceptance/linux-mint-22.3.md](docs/acceptance/linux-mint-22.3.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE), [THIRD_PARTY.md](THIRD_PARTY.md), and [LICENSES/README](LICENSES/README).
