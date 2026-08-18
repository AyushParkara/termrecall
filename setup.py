# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        source = Path(__file__).parent / "native" / "termrecall-nonblock.c"
        output = Path(self.build_lib) / "termrecall" / "libexec" / "termrecall-nonblock"
        output.parent.mkdir(parents=True, exist_ok=True)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(
            [*compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(output)],
            check=True,
        )
        output.chmod(0o755)


setup(cmdclass={"build_py": build_py})
