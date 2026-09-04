#!/usr/bin/python3

import sys
import json
import os
import stat
from datetime import datetime, timezone

TARGET = "/usr/local/bin/sys-maintenance"
LOGFILE = "/var/ossec/logs/active-responses.log"
EXPECTED_RULE = "100202"


def log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    with open(LOGFILE, "a") as f:
        f.write(f"{timestamp} bsc-suid-hardening: {message}\n")


def main():
    line = sys.stdin.readline()

    if not line:
        log("ERROR no JSON received on STDIN")
        return 1

    try:
        message = json.loads(line)
    except json.JSONDecodeError as exc:
        log(f"ERROR invalid JSON: {exc}")
        return 1

    command = message.get("command")

    if command != "add":
        log(f"IGNORED command={command}")
        return 0

    alert = message.get("parameters", {}).get("alert", {})
    rule_id = str(alert.get("rule", {}).get("id", ""))

    if rule_id != EXPECTED_RULE:
        log(f"IGNORED unexpected rule_id={rule_id}")
        return 0

    try:
        st = os.lstat(TARGET)
    except FileNotFoundError:
        log(f"ERROR target_not_found target={TARGET}")
        return 1

    if stat.S_ISLNK(st.st_mode):
        log(f"ERROR target_is_symlink target={TARGET}")
        return 1

    if not stat.S_ISREG(st.st_mode):
        log(f"ERROR target_not_regular_file target={TARGET}")
        return 1

    if st.st_uid != 0:
        log(f"ERROR target_not_root_owned uid={st.st_uid} target={TARGET}")
        return 1

    before = stat.S_IMODE(st.st_mode)

    if before & stat.S_ISUID:
        after = before & ~stat.S_ISUID
        os.chmod(TARGET, after)

        verified = stat.S_IMODE(os.stat(TARGET).st_mode)

        log(
            f"SUCCESS rule_id={rule_id} "
            f"target={TARGET} "
            f"mode_before={before:04o} "
            f"mode_after={verified:04o} "
            f"action=removed_suid"
        )
    else:
        log(
            f"NO_CHANGE rule_id={rule_id} "
            f"target={TARGET} "
            f"mode={before:04o} "
            f"reason=suid_not_set"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
