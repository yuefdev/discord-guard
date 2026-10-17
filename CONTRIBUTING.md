# Contributing

Python 3.11+ and Windows 11 x64 are the development baseline. Install the pinned
development requirements and run the focused checks before sending a change:

```powershell
python -m pip install -r requirements-build.txt
$env:PYTHONPATH = 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -v
python -B native\build.py --output "$env:TEMP\GuardCoreBuild"
```

Keep launch decisions outside the UI. Missing evidence must not be converted to
an enabled state. Ordinary inspection, user isolation and live driver status are
different claims. Tests use synthetic data and must not change the real machine's
accounts, startup settings, signing mode or security configuration.

Driver changes require a disposable VM, Driver Verifier and the runtime matrix
in `native/README.md` before promotion. Include compatibility, update and recovery
results. An ordinary CI build does not establish those results.

Changes are provided under the root MIT licence. Dependency licence terms remain
with their respective owners. The project is not affiliated with Discord or Riot.
