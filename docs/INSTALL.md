# Per-user installation

## Requirements

- Linux Mint 22.3 Cinnamon
- GNOME Terminal and interactive Bash
- Python 3.12 with `venv`
- A C11 compiler (`cc`) for the native nonblocking helper

## Bootstrap with ./install.sh (primary method)

From a verified source checkout, the POSIX bootstrap owns application fresh install and upgrade. It refuses root/sudo, checks the prerequisites, runs the source-tree `installer_probe.py` as the authoritative read-only planner, renders a dry-run plan on request, and on real execution builds an isolated wheel, stages a delegate venv, and calls `installer_probe.py launch-delegate` which re-plans read-only, verifies digest/drift, and spawns the hidden installed bootstrap with bounded canonical request/plan descriptors. The shell never substitutes the running process, performs unchecked recursive deletion, escalates privileges, or creates payload files, FIFOs, or process substitution.

```bash
./install.sh --full
```

### Modes and integration states

```text
./install.sh [--bash STATE] [--autostart STATE] [--chooser STATE]
./install.sh MODE [--bash STATE] [--autostart STATE] [--chooser STATE] [--dry-run]
MODE  := --full | --no-autostart | --commands-only | --upgrade
STATE := enable | disable | preserve
```

Defaults: `--full=(enable,enable,enable)`, `--no-autostart=(enable,disable,preserve)`, `--commands-only=(preserve,preserve,preserve)`, `--upgrade=(preserve,preserve,preserve)`. Interactive mode (no `MODE`) prompts for the three states with defaults `(enable,disable,preserve)`. `--commands-only` rejects non-`preserve` overrides; `--no-autostart` rejects `--autostart enable`; `--upgrade` rejects every non-`preserve` override. `--dry-run` requires exactly one noninteractive `MODE` and renders the validated plan with zero writes before any `mktemp`, build, or delegate invocation.

Do not run the bootstrap as root or under `sudo`. It never contacts a package index during the offline wheel build.

## Reconfigure installed integrations (no reinstall)

Public installed commands plan/apply only Bash, autostart, and chooser changes against the manifest-verified current installation. They never build, pip-install, create/switch/delete generations, or remove the application.

```bash
termrecall setup --bash STATE --autostart STATE --chooser STATE [--dry-run]
termrecall autostart enable|disable
termrecall chooser enable|disable
termrecall doctor
```

`setup` defaults every omitted state to `preserve` and rejects application modes, `--upgrade`, source/wheel/probe/descriptor flags, and positionals.

## Upgrade

```bash
./install.sh --upgrade
```

`--upgrade` preserves all integration states and replaces only the application generation/links; the manifest is rewritten last. Keep state/config backups private (`0700` directory, `0600` files).

## Uninstall

Uninstall is manifest-driven and removes only verified, manifest-owned objects. `--yes` is noninteractive and selects a consistent application + Bash + autostart removal, preserving chooser and state.

```bash
termrecall uninstall --yes                       # removes app + Bash + autostart; keeps chooser/state
termrecall uninstall --yes --purge-state         # also quarantines and deletes recovery state
```

Interactive `uninstall` (no `--yes`) asks about application, Bash, autostart, chooser, and state separately before any mutation. Removing the application requires Bash and autostart removal; the chooser may remain. `--purge-state` without `--yes` is a usage error. State purge uses a same-filesystem private quarantine and never prints state descendants.
