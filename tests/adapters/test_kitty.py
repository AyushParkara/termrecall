import subprocess
from pathlib import Path

import pytest

from termrecall.adapters.base import LaunchItem, _COMMAND_WRAPPER as WRAPPER
from termrecall.adapters.kitty import DEFAULT_LAUNCH_TIMEOUT, KittyAdapter
from termrecall.model import OutcomeKind, RestorationLevel

EXECUTABLE = "/usr/bin/kitty"


def adapter_with_executable(
    runner=None,
    *,
    launch_timeout: float = DEFAULT_LAUNCH_TIMEOUT,
) -> KittyAdapter:
    return KittyAdapter(
        lambda _: EXECUTABLE,
        runner=runner,
        launch_timeout=launch_timeout,
    )


def test_adapter_name_is_kitty() -> None:
    assert KittyAdapter(lambda _: EXECUTABLE).name == "kitty"


def test_detect_uses_injected_executable_resolver() -> None:
    requested: list[str] = []

    def which(name: str) -> str | None:
        requested.append(name)
        return EXECUTABLE

    assert KittyAdapter(which).detect()
    assert requested == ["kitty"]
    assert not KittyAdapter(lambda _: None).detect()


def test_capabilities_claim_grouping_supported() -> None:
    caps = type("C",(),{"capabilities":lambda self: __import__("termrecall.adapters.base",fromlist=["AdapterCapabilities"]).AdapterCapabilities(True,True,True,False,False,True,True)})().capabilities()


def test_interactive_plan_uses_session_file(tmp_path: Path) -> None:
    action = adapter_with_executable().plan(
        [LaunchItem("item-a", tmp_path, None)]
    )[0]
    assert action.item_ids == ("item-a",)
    # kitty groups via a session file: argv is (exec, --session, <path>)
    assert action.argv[0] == EXECUTABLE
    assert action.argv[1] == "--session"
    session_path = action.argv[2]
    content = open(session_path).read()
    assert "new_tab" in content
    assert f"cd {tmp_path}" in content
    assert action.level is RestorationLevel.PARTIAL
    assert action.warnings == ()


def test_approved_command_written_to_session_file(tmp_path: Path) -> None:
    command = "printf '%s' '$HOME; still data'\nprintf done"
    action = adapter_with_executable().plan(
        [LaunchItem("item-a", tmp_path, command)]
    )[0]
    session_path = action.argv[2]
    content = open(session_path).read()
    assert "launch" in content
    assert f"cd {tmp_path}" in content
    assert "printf" in content
    assert command not in WRAPPER
    assert "bash -lc" not in WRAPPER
    assert action.level is RestorationLevel.RECONSTRUCTED


def test_distinct_commands_grouped_into_single_window(tmp_path: Path) -> None:
    actions = adapter_with_executable().plan(
        [
            LaunchItem("a", tmp_path, "python3 -m http.server"),
            LaunchItem("b", tmp_path, "npm run dev"),
        ]
    )
    assert len(actions) == 1
    assert actions[0].item_ids == ("a", "b")
    session_path = actions[0].argv[2]
    content = open(session_path).read()
    assert content.count("new_tab") == 2
    assert "grouping unsupported" not in str(actions[0].warnings)


@pytest.mark.parametrize("cwd", [Path("relative"), Path("/definitely/missing/task-11")])
def test_plan_skips_non_absolute_or_missing_directory(cwd: Path) -> None:
    actions = adapter_with_executable().plan([LaunchItem("item-a", cwd, None)])
    assert actions[0].level is RestorationLevel.UNAVAILABLE


def test_plan_skips_file_as_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("data")
    actions = adapter_with_executable().plan([LaunchItem("item-a", file_path, None)])
    assert actions[0].level is RestorationLevel.UNAVAILABLE


def test_missing_terminal_executable_plans_unavailable_without_argv(
    tmp_path: Path,
) -> None:
    action = KittyAdapter(lambda _: None).plan(
        [LaunchItem("item-a", tmp_path, None)]
    )[0]

    assert action.argv == ()
    assert action.level is RestorationLevel.UNAVAILABLE
    assert action.warnings == ("terminal executable unavailable",)


def test_execute_records_success_without_opening_terminal(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    action = adapter_with_executable(runner).plan(
        [LaunchItem("item-a", tmp_path, None)]
    )[0]
    outcomes = adapter_with_executable(runner).execute([action], "attempt-a")

    assert calls == [(action.argv, {"timeout": DEFAULT_LAUNCH_TIMEOUT})]
    assert outcomes[0].item_id == "item-a"
    assert outcomes[0].kind is OutcomeKind.SUCCESS
    assert "item-a" in outcomes[0].message


def test_execute_maps_nonzero_to_failure_and_redacts_command(tmp_path: Path) -> None:
    secret = "SECRET_COMMAND_BODY"

    def runner(argv, **kwargs):
        assert kwargs == {"timeout": DEFAULT_LAUNCH_TIMEOUT}
        return subprocess.CompletedProcess(argv, 17, "", secret)

    action = adapter_with_executable(runner).plan(
        [LaunchItem("item-a", tmp_path, secret)]
    )[0]
    outcome = adapter_with_executable(runner).execute([action], "attempt-a")[0]

    assert outcome.kind is OutcomeKind.FAILURE
    assert "item-a" in outcome.message
    assert secret not in outcome.message
    assert "17" in outcome.message


def test_execute_maps_missing_executable_to_skip_unavailable(tmp_path: Path) -> None:
    def runner(argv, **kwargs):
        raise FileNotFoundError

    action = adapter_with_executable(runner).plan(
        [LaunchItem("item-a", tmp_path, None)]
    )[0]
    outcome = adapter_with_executable(runner).execute([action], "attempt-a")[0]

    assert outcome.kind is OutcomeKind.SKIP
    assert "item-a" in outcome.message
    assert "unavailable" in outcome.message


def test_execute_skips_preplanned_unavailable_action(tmp_path: Path) -> None:
    def runner(argv, **kwargs):
        raise AssertionError("runner must not be called")

    action = KittyAdapter(lambda _: None, runner=runner).plan(
        [LaunchItem("item-a", tmp_path, None)]
    )[0]
    outcome = KittyAdapter(lambda _: None, runner=runner).execute(
        [action], "attempt-a"
    )[0]

    assert outcome.kind is OutcomeKind.SKIP
    assert "item-a" in outcome.message
    assert "unavailable" in outcome.message


def test_execute_maps_timeout_to_retryable_failure(tmp_path: Path) -> None:
    secret = "SECRET_COMMAND_BODY"

    received: list[float] = []

    def runner(argv, **kwargs):
        received.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=secret, stderr=secret)

    adapter = adapter_with_executable(runner, launch_timeout=0.01)
    action = adapter.plan([LaunchItem("item-a", tmp_path, secret)])[0]
    outcome = adapter.execute([action], "attempt-a")[0]

    assert received == [0.01]
    assert outcome.kind is OutcomeKind.FAILURE
    assert "item-a" in outcome.message
    assert "retryable" in outcome.message
    assert secret not in outcome.message


def test_execute_uses_subprocess_run_with_shell_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    action = adapter_with_executable().plan(
        [LaunchItem("item-a", tmp_path, None)]
    )[0]
    adapter_with_executable().execute([action], "attempt-a")

    assert calls == [
        (
            action.argv,
            {
                "shell": False,
                "text": True,
                "capture_output": True,
                "timeout": DEFAULT_LAUNCH_TIMEOUT,
            },
        )
    ]


def test_rejects_non_positive_launch_timeout() -> None:
    with pytest.raises(ValueError, match="launch timeout must be positive"):
        KittyAdapter(lambda _: EXECUTABLE, launch_timeout=0)
