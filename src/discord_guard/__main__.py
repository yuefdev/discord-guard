"""Entrypoint shared by source runs and the packaged Windows application."""

import argparse
import ctypes
import json
import os
import sys

from discord_guard.core import LOCAL_USER_SID, decide
from discord_guard import windows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="DiscordGuard isolated Windows launcher")
    parser.add_argument("--diagnose", action="store_true", help="Print launch checks; do not change the computer")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--setup", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--origin-sid", help=argparse.SUPPRESS)
    parser.add_argument("--autostart", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.autostart and (args.setup or args.smoke_test or args.diagnose or args.origin_sid):
        parser.error("--autostart must be used alone")
    if args.diagnose:
        try:
            result = decide(windows.inspect()).to_dict()
            if sys.stdout is not None:
                print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0 if result["launch_allowed"] else 2
        except windows.GuardError as error:
            if sys.stdout is not None:
                print(json.dumps({"launch_allowed": False, "error": str(error)}, ensure_ascii=True))
            return 1
    if args.setup and (not windows.is_admin() or not args.origin_sid or not LOCAL_USER_SID.fullmatch(args.origin_sid)):
        if os.name == "nt":
            ctypes.windll.user32.MessageBoxW(None, "Kurulumu ana penceredeki düğmeden, Windows yönetici onayıyla başlatın.",
                                            "DiscordGuard", 0x10)
        return 1
    if os.name == "nt":
        try:
            ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        except (AttributeError, OSError):
            pass
    startup_error = None
    if args.autostart:
        try:
            windows.run_autostart()
            return 0
        except windows.GuardError as error:
            startup_error = str(error)
        except Exception:
            startup_error = "Otomatik başlatma tamamlanamadı. Discord’un denetimli açılışı yapılmadı."
    from discord_guard.gui import show
    show(setup_origin_sid=args.origin_sid if args.setup else None, smoke_test=args.smoke_test,
         startup_error=startup_error)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
