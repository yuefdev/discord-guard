# Third-party notices and rebuilding

DiscordGuard's original code is MIT-licensed. Its dependencies are not relicensed.

| Component | Version | Licence / source |
| --- | --- | --- |
| Python | Build's Python version | PSF, <https://www.python.org/downloads/source/> |
| PySide6 / Shiboken6 / Qt | 6.11.2 | LGPL-3.0 option and applicable Qt component licences, <https://download.qt.io/official_releases/QtForPython/pyside6/> and <https://download.qt.io/official_releases/qt/6.11/6.11.2/submodules/> |
| PyInstaller bootloader | 6.22.3 | GPL with bootloader exception, <https://github.com/pyinstaller/pyinstaller/tree/v6.22.3> |
| MSVC runtime | Toolchain's version | Microsoft redistributable terms |
| Microsoft SDK / WDK | SDK 26100 / WDK 10.0.26100.6584 | Microsoft licence in the downloaded kit; kits are not redistributed in the release |

Qt libraries are dynamically loaded. For redistribution the release script
bundles GNU GPLv3/LGPLv3 texts and Python's licence and records the dependency
versions. Qt's component-specific third-party notices from the installed wheel
are also copied when available. Commercial Qt terms are not substituted for the
LGPL option. Distributors must make corresponding dependency source and notices
available as required; use the exact release's source archives, not `main`.

The complete MIT application source and build scripts allow rebuilding with a
modified LGPL library. Do not prohibit reverse engineering for debugging library
modifications. A **directory-based build** is the redistribution default so users
can replace compatible Qt DLLs in `_internal/PySide6/Qt/bin` (some wheel layouts
place them directly in `_internal/PySide6`). The optional one-file developer
build is not the published binary layout.

```powershell
python -m pip install -r requirements-build.txt
.\build.ps1 -OutputRoot "$env:TEMP\DiscordGuardBuild" -Layout onedir
```

The project does not include the proprietary Discord client. The official client
is installed separately from Discord. Product names remain their owners' marks.
