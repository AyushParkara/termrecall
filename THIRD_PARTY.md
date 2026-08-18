# Third-party notices

TermRecall runtime code has no mandatory third-party Python dependency.

Development and test tooling is not bundled into the installed runtime:

- pytest, MIT License, https://github.com/pytest-dev/pytest
- pytest-asyncio, Apache License 2.0, https://github.com/pytest-dev/pytest-asyncio
- setuptools, MIT License, https://github.com/pypa/setuptools

The installed native nonblocking helper in `native/termrecall-nonblock.c` is project-authored and distributed under GPL-3.0-or-later. The packaged Bash hook and Cinnamon desktop file are also project-authored. System-provided Python, Bash, GNOME Terminal, Cinnamon, libc, and the C compiler are external platform components and are not redistributed in the wheel.

No copied third-party source is currently vendored. If vendored code or assets are added, place their exact license texts under `LICENSES/` and update this notice before release.
