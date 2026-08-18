# Linux Mint 22.3 manual acceptance

This is a release checklist for a disposable or backed-up Linux Mint 22.3 Cinnamon account. It intentionally opens GNOME Terminal windows and reboots. Do not run it from an automated or non-graphical development session.

Record date, host version, package wheel hash, tester, and pass/fail evidence.

## Preconditions

1. Install the wheel per `docs/INSTALL.md` without root.
2. Confirm `echo "$XDG_CURRENT_DESKTOP"` reports `X-Cinnamon`, `gnome-terminal --version` succeeds, and `termrecall doctor` is actionable.
3. Confirm the installed Bash hook and autostart paths are user-owned and not symlinks to unexpected locations.
4. Use only benign commands and temporary directories. Do not use secrets in test commands.

## Same-boot sequence

1. Create observable directories and record the test root:
   ```bash
   TR_ACCEPT=$(mktemp -d "$HOME/termrecall-accept.XXXXXX")
   mkdir "$TR_ACCEPT"/{A,B,C,D}
   printf '%s\n' "$TR_ACCEPT"
   ```
2. Open four tabs explicitly:
   ```bash
   gnome-terminal --tab --working-directory="$TR_ACCEPT/A" \
     --tab --working-directory="$TR_ACCEPT/B" \
     --tab --working-directory="$TR_ACCEPT/C" \
     --tab --working-directory="$TR_ACCEPT/D"
   ```
3. Leave A idle. In B run `python3 -m http.server 8765`; verify `curl -I http://127.0.0.1:8765/` succeeds.
4. In C run `exit`. In the surviving control tab, run `termrecall snapshot` and then `termrecall list`; record the output and verify no C entry appears. This is the observable explicit-exit exclusion check.
5. Close D using GNOME Terminal's tab-close GUI, not `exit`. Run `termrecall list` again; D must now be offered as `same_boot_dead`, while still-live A and B remain absent.
6. Run `termrecall restore --directory-only`, select D, and verify the new tab reports `pwd` as `$TR_ACCEPT/D`. Confirm no command started before selection/approval.
7. Induce a reversible adapter failure without changing system packages:
   ```bash
   mv "$TR_ACCEPT/D" "$TR_ACCEPT/D.offline"
   termrecall restore --directory-only
   ```
   Verify the item visibly falls back to `$TR_ACCEPT`, or reports a retryable failure, and no command runs. Restore the resource with `mv "$TR_ACCEPT/D.offline" "$TR_ACCEPT/D"`, retry, and verify success is not duplicated.
8. Stop the benign service with `jobs -p | xargs -r kill`, then confirm `curl http://127.0.0.1:8765/` fails. Preserve `$TR_ACCEPT` for the reboot sequence.

## Reboot/logout sequence

1. Repeat with an idle tab, benign service tab, explicit-`exit` tab, and GUI-closed tab.
2. Snapshot and reboot the test host normally.
3. After Cinnamon login, verify exactly one chooser appears when recovery exists.
4. Verify prior-boot ambiguous/active tabs are offered and the explicit-`exit` tab remains excluded.
5. Restore directories first. Confirm no command starts.
6. Separately approve the benign service command and verify exactly one restart in the correct directory.
7. Verify failures remain retryable and successes are suppressed from retry.
8. Run `termrecall status` and `termrecall doctor`; record output with no command or secret literals.
9. Capture the workspace ID from `termrecall list`, run `termrecall discard WORKSPACE_ID`, type the exact confirmation when prompted, then verify `termrecall list` has no workspace and `termrecall status` reports zero recovery items.
10. Clean up only acceptance resources:
    ```bash
    pkill -f 'python3 -m http.server 8765' || true
    rm -rf -- "$TR_ACCEPT"
    ```
    Do not remove the product state directory as part of acceptance; discard is the behavior under test.

## Desktop smoke

Only after the graphical test account is prepared:

```bash
TERMRECALL_DESKTOP_TEST=1 python3.12 -m pytest \
  tests/desktop/test_gnome_acceptance.py -v -m desktop
```

Visually confirm the interactive item opens in the temporary directory and no command executes for it. The approved item may run only after the explicit test opt-in.

V1 release acceptance requires this checklist and desktop smoke to pass on the verified host. A skip is not a pass.
