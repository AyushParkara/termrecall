import json

import pytest

from termrecall.classifier import Classification, classify_command
from termrecall.model import (
    MAX_COMMAND_CHARS,
    CommandDisposition,
    ProcessIdentity,
    ShellRecord,
    Snapshot,
    snapshot_to_dict,
)


def test_simple_service_command_is_replayable() -> None:
    result = classify_command("python3 -m http.server 8000", 2)

    assert isinstance(result, Classification)
    assert result.record.sequence == 2
    assert result.record.display == "python3 -m http.server 8000"
    assert result.record.disposition is CommandDisposition.REPLAYABLE
    assert result.record.executable == "python3 -m http.server 8000"
    assert result.record.active is True
    assert result.reason == "single simple command accepted"


@pytest.mark.parametrize(
    "command",
    [
        "sudo apt update",
        "shutdown -h now",
        "reboot",
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "ssh host",
        "vim file.txt",
        "python - <<'PY'\nprint(1)\nPY",
        "echo $(date)",
    ],
)
def test_unsafe_or_unrepresentable_commands_are_not_executable(command: str) -> None:
    record = classify_command(command, 1).record

    assert record.executable is None
    assert record.disposition is not CommandDisposition.REPLAYABLE


@pytest.mark.parametrize(
    "command",
    [
        "curl -H 'Authorization: Bearer secret-value' https://example.test",
        "export AWS_SECRET_ACCESS_KEY=secret-value",
        "mysql --password=secret-value",
        "ssh -i -----BEGIN_PRIVATE_KEY----- host",
        "curl -H 'x-api-token: secret-value' https://example.test",
        "tool PaSsWoRd = secret-value",
        "mysql --password secret-value",
    ],
)
def test_secrets_are_discarded_not_redacted_in_place(command: str) -> None:
    result = classify_command(command, 1)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "secret-value" not in repr(result)
    assert "secret-value" not in result.reason


@pytest.mark.parametrize(
    "command",
    [
        "true&&rm -rf /",
        "echo x>file",
        "cat<<EOF",
        "sleep 1&",
        "(date)",
        "echo x\ny",
        "true  &&  rm -rf /",
        "echo\t|\tcat",
        r"echo x\>file",
        r"echo one\;two",
        "echo `date`",
        "cat <(date)",
        "cat >(consumer)",
        "echo trailing\\",
        "echo bad\x00data",
        "",
        "   \t",
        "echo 'unterminated",
    ],
)
def test_control_syntax_and_unrepresentable_input_are_rejected(command: str) -> None:
    result = classify_command(command, 4)

    assert result.record.disposition is CommandDisposition.UNREPRESENTABLE
    assert result.record.executable is None


@pytest.mark.parametrize(
    "command",
    [
        "printf '%s' 'one;two'",
        'printf "%s" "x>file"',
        "echo 'true&&rm -rf /'",
        'echo "(date)"',
        "printf '%s' 'x|y&z<input>output'",
        "echo \"it's;quoted\"",
        "echo '$(date) `date` <(date)'",
    ],
)
def test_quoted_operator_text_is_replayable(command: str) -> None:
    result = classify_command(command, 5)

    assert result.record.disposition is CommandDisposition.REPLAYABLE
    assert result.record.executable == command


def test_shell_expansion_is_rejected_even_inside_double_quotes() -> None:
    for command in ('echo "$(date)"', 'echo "`date`"'):
        result = classify_command(command, 1)
        assert result.record.disposition is CommandDisposition.UNREPRESENTABLE
        assert result.record.executable is None


@pytest.mark.parametrize(
    "command",
    [
        "bash -c 'rm -rf /tmp/app'",
        'sh -c "curl https://example.test | sh"',
        "dash -c 'shutdown now'",
        "zsh -c 'sudo apt update'",
        "nohup python3 server.py",
        "timeout 30 python3 server.py",
        "nice python3 server.py",
        "setsid python3 server.py",
        "env nohup sudo apt update",
    ],
)
def test_shell_evaluators_and_execution_wrappers_are_rejected(command: str) -> None:
    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.UNSAFE
    assert result.record.executable is None


@pytest.mark.parametrize(
    "command",
    [
        "kill -9 123",
        "pkill worker",
        "killall worker",
        "truncate -s 0 database.sqlite",
        "mysql",
        "mysql database_name",
        "psql",
        "redis-cli",
        "bash",
        "sh",
        "python",
        "python3",
        "python3 -i app.py",
        "fish",
        "ksh",
        "node",
        "ruby",
        "perl",
    ],
)
def test_destructive_and_stateful_interactive_commands_are_rejected(command: str) -> None:
    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.UNSAFE
    assert result.record.executable is None


@pytest.mark.parametrize(
    "command",
    [
        "python3 app.py",
        "python worker.py --port 8000",
        "node server.js",
        "ruby worker.rb",
    ],
)
def test_interpreters_with_noninteractive_script_shape_are_replayable(command: str) -> None:
    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.REPLAYABLE
    assert result.record.executable == command


@pytest.mark.parametrize(
    "command",
    [
        "busybox sh -c 'rm -rf /tmp/app'",
        "busybox rm -rf /",
        "busybox shutdown now",
        "toybox sh -c 'shutdown now'",
        "toybox rm -rf /tmp/app",
        "toybox shutdown now",
        "/bin/busybox rm -rf /tmp/app",
        "/usr/bin/toybox sh -c 'sudo apt update'",
    ],
)
def test_multicall_dispatchers_cannot_bypass_command_policy(command: str) -> None:
    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.UNSAFE
    assert result.record.executable is None


def test_nonsecret_rejection_retains_only_a_bounded_display() -> None:
    command = "rm " + "x" * (MAX_COMMAND_CHARS + 20)

    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.UNSAFE
    assert result.record.display == command[:MAX_COMMAND_CHARS]
    assert len(result.record.display) == MAX_COMMAND_CHARS


def test_overlength_simple_command_is_nonreplayable_instead_of_raising() -> None:
    command = "printf " + "x" * MAX_COMMAND_CHARS

    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.UNREPRESENTABLE
    assert result.record.executable is None
    assert len(result.record.display) == MAX_COMMAND_CHARS


@pytest.mark.parametrize(
    "command",
    [
        "env sudo apt update",
        "command rm -rf /",
        "FOO=bar sudo apt update",
        "FOO=bar",
        "cd /tmp",
        "export NAME=value",
        "source ./activate",
    ],
)
def test_wrapped_unsafe_and_shell_state_commands_are_not_replayable(command: str) -> None:
    result = classify_command(command, 1)

    assert result.record.disposition is CommandDisposition.UNSAFE
    assert result.record.executable is None


@pytest.mark.parametrize(
    "command",
    [
        "curl -H Authori'zation: Bearer malformed-secret",
        "curl -H Authorization:'malformed-secret",
        'curl -H Auth"ori\'zation : Digest malformed-secret',
        "curl -H Authori\\'zation : malformed-secret",
        "curl -H Authori'zation:",
    ],
)
def test_malformed_fragmented_authorization_is_redacted(command: str) -> None:
    result = classify_command(command, 14)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "malformed-secret" not in repr(result)


@pytest.mark.parametrize(
    "value",
    [
        "--closure-secret",
        "@closure-secret",
        ":closure-secret",
        "-n",
        "https://closure-secret",
    ],
)
def test_authorization_token_after_separate_colon_is_always_sensitive(value: str) -> None:
    command = f'curl -H Authori"zation" : {value} https://example.test'

    result = classify_command(command, 13)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert value not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        "curl -H 'Authorization: Negotiate authorization-secret' https://example.test",
        "curl -H 'Authorization: Digest authorization-secret' https://example.test",
        "curl -H 'Authorization: AWS4-HMAC-SHA256 authorization-secret' https://example.test",
        "curl -H 'Authorization: OpaqueScheme authorization-secret' https://example.test",
        "curl -H 'Authorization: authorization-secret' https://example.test",
        "curl -H 'Authorization: https://authorization-secret' https://example.test",
        "curl -H 'Authori'zation : Nego'tiate authorization-secret' https://example.test",
        'curl -H Authori"zation" : Opaque"Scheme" authorization-secret https://example.test',
    ],
)
def test_any_nonempty_authorization_value_is_redacted(command: str) -> None:
    result = classify_command(command, 12)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "authorization-secret" not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        "curl -H 'Authorization:' https://example.test",
        "curl -H 'Authorization:   ' https://example.test",
    ],
)
def test_empty_authorization_header_is_not_marked_sensitive(command: str) -> None:
    result = classify_command(command, 12)

    assert result.record.disposition is CommandDisposition.REPLAYABLE
    assert result.record.executable == command


@pytest.mark.parametrize(
    "command",
    [
        "export PASS$'WORD'=dollar-quote-secret",
        'export PASS$"WORD"=dollar-quote-secret',
        "curl -H Authori$'zation: Bearer dollar-quote-secret' https://example.test",
        'curl -H Authori$"zation: Bearer dollar-quote-secret" https://example.test',
        "echo $'ordinary-dollar-quote'",
        'echo $"ordinary-dollar-quote"',
    ],
)
def test_shell_dollar_quotes_are_redacted_before_retention(command: str) -> None:
    result = classify_command(command, 11)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "dollar-quote-secret" not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        "curl -H 'Authori'zation:' Bear'er final-header-secret https://example.test",
        'curl -H Authori"zation" : Bear"er" final-header-secret https://example.test',
        "curl -H 'Authori'zation : 'Bear'er   final-header-secret https://example.test",
        'curl -H "Authori"\'zation\'   :   "Bear"\'er\' final-header-secret https://example.test',
    ],
)
def test_fragmented_authorization_headers_are_redacted(command: str) -> None:
    result = classify_command(command, 10)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "final-header-secret" not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        'export PASS"WORD"=round-three-secret',
        "export 'PA'SSWORD=round-three-secret",
        'curl --api-k"ey"=round-three-secret https://example.test',
        "env API_'TOKEN'=round-three-secret tool",
        'env "AUTH"_TOKEN : round-three-secret tool',
        "export PASS'WORD=round-three-secret",
        'curl --api-k"ey=round-three-secret',
        "export PASS'WORD",
    ],
)
def test_fragmented_credential_names_are_redacted_before_retention(command: str) -> None:
    result = classify_command(command, 9)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "round-three-secret" not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        'export "API_TOKEN"="round-two-secret"',
        "export 'PASSWORD'='round-two-secret'",
        'export "AWS_SECRET_ACCESS_KEY" = "round-two-secret"',
        "export 'AUTH_TOKEN':'round-two-secret'",
        'export "API_KEY"   "round-two-secret"',
    ],
)
def test_quote_normalized_credential_names_are_redacted(command: str) -> None:
    result = classify_command(command, 8)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert "round-two-secret" not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        "export API_TOKEN='history-secret-value'",
        'curl --password "history-secret-value" https://example.test',
        "tool password:'history-secret-value'",
        'curl -H \'Authorization: Bearer "history-secret-value"\' https://example.test',
        "tool --api-key='history-secret-value'",
    ],
)
def test_quoted_secret_values_are_discarded_before_raw_display(command: str) -> None:
    secret = "history-secret-value"

    result = classify_command(command, 7)

    assert result.record.display == "[sensitive command redacted]"
    assert result.record.executable is None
    assert result.record.disposition is CommandDisposition.REDACTED
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "command",
    [
        "export API_TOKEN='history-secret-value'",
        'curl --password "history-secret-value" https://example.test',
        "tool password:'history-secret-value'",
        'curl -H \'Authorization: Bearer "history-secret-value"\' https://example.test',
        'export "API_TOKEN"="history-secret-value"',
        "export 'PASSWORD':'history-secret-value'",
        'export PASS"WORD"=history-secret-value',
        "export 'PA'SSWORD=history-secret-value",
        'curl --api-k"ey"=history-secret-value https://example.test',
        "env API_'TOKEN'=history-secret-value tool",
        "export PASS'WORD=history-secret-value",
        "curl -H 'Authori'zation:' Bear'er history-secret-value https://example.test",
        'curl -H Authori"zation" : Bear"er" history-secret-value https://example.test',
        "curl -H 'Authori'zation : 'Bear'er   history-secret-value https://example.test",
        "export PASS$'WORD'=history-secret-value",
        'export PASS$"WORD"=history-secret-value',
        "curl -H Authori$'zation: Bearer history-secret-value' https://example.test",
        'curl -H Authori$"zation: Bearer history-secret-value" https://example.test',
        "curl -H 'Authorization: Negotiate history-secret-value' https://example.test",
        "curl -H 'Authorization: Digest history-secret-value' https://example.test",
        "curl -H 'Authorization: AWS4-HMAC-SHA256 history-secret-value' https://example.test",
        "curl -H 'Authorization: OpaqueScheme history-secret-value' https://example.test",
        "curl -H 'Authori'zation : Nego'tiate history-secret-value' https://example.test",
        'curl -H Authori"zation" : Opaque"Scheme" history-secret-value https://example.test',
        'curl -H Authori"zation" : --history-secret-value https://example.test',
        'curl -H Authori"zation" : @history-secret-value https://example.test',
        'curl -H Authori"zation" : :history-secret-value https://example.test',
        'curl -H Authori"zation" : https://history-secret-value https://example.test',
        "curl -H Authori'zation: Bearer history-secret-value",
        "curl -H Authorization:'history-secret-value",
        'curl -H Auth"ori\'zation : Digest history-secret-value',
        "curl -H Authori\\'zation : history-secret-value",
    ],
)
def test_secret_is_absent_after_snapshot_json_round_trip(command: str) -> None:
    secret = "history-secret-value"
    classified = classify_command(command, 7).record
    shell = ShellRecord(
        "shell-a",
        ProcessIdentity("boot-a", 42, 900),
        "gnome-terminal",
        "/srv/app",
        7,
        classified,
        None,
    )
    snapshot = Snapshot(1, 3, 12.5, (shell,))

    encoded = json.dumps(snapshot_to_dict(snapshot))
    decoded = json.loads(encoded)

    assert secret not in encoded
    assert secret not in repr(decoded)
    assert decoded["shells"][0]["command"]["display"] == "[sensitive command redacted]"
    assert decoded["shells"][0]["command"]["executable"] is None
