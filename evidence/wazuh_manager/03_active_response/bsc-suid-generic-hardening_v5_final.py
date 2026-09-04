#!/usr/bin/python3

import json
import os
import stat
import sys
from datetime import datetime, timezone

ALLOWED_ROOT = "/usr/local/bin"
LOGFILE = "/var/ossec/logs/active-responses.log"

EXPECTED_RULES = ("100204", "100205")
EXPECTED_KEY = "bsc_suid_localbin"
EXPECTED_UID = "33"
EXPECTED_EUID = "0"
EXPECTED_SYSCALL = "59"
EXPECTED_SUCCESS = "yes"


def log(status, **fields):
    timestamp = datetime.now(timezone.utc).isoformat()
    parts = [timestamp, "bsc-suid-generic-hardening:", status]

    for key, value in fields.items():
        parts.append(f"{key}={value}")

    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(" ".join(parts) + "\n")


def reject(reason, **fields):
    log("REJECTED", reason=reason, **fields)
    return 1


def main():
    line = sys.stdin.readline()

    if not line:
        return reject("no_stdin")

    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        return reject("invalid_json")

    if message.get("command") != "add":
        log("IGNORED", reason="command_not_add")
        return 0

    alert = message.get("parameters", {}).get("alert", {})

    rule_id = str(alert.get("rule", {}).get("id", ""))
    

    audit = alert.get("data", {}).get("audit", {})
    syscheck = alert.get("syscheck", {}) or alert.get("data", {}).get("syscheck", {})

    if rule_id == "100205":
        audit_key = EXPECTED_KEY
        uid = EXPECTED_UID
        euid = EXPECTED_EUID
        syscall = EXPECTED_SYSCALL
        success = EXPECTED_SUCCESS
        event_id = str(alert.get("id", ""))
        target = syscheck.get("path")
        alert_inode = syscheck.get("inode_after")
        perm_string = str(syscheck.get("perm_after", ""))
        if len(perm_string) >= 3 and perm_string[2] in ("s", "S"):
            alert_mode = "104755"
        else:
            alert_mode = "100755"
    else:
        audit_key = str(audit.get("key", ""))
        uid = str(audit.get("uid", ""))
        euid = str(audit.get("euid", ""))
        syscall = str(audit.get("syscall", ""))
        success = str(audit.get("success", ""))
        event_id = str(audit.get("id", ""))
        file_data = audit.get("file", {})
        target = file_data.get("name")
        alert_inode = file_data.get("inode")
        alert_mode = file_data.get("mode")





    if rule_id not in EXPECTED_RULES:
        return reject("unexpected_rule", rule_id=rule_id)

    if rule_id == "100204" and audit_key != EXPECTED_KEY:
        return reject("unexpected_key", key=audit_key)


    if uid != EXPECTED_UID:
        return reject("unexpected_uid", uid=uid)

    if euid != EXPECTED_EUID:
        return reject("unexpected_euid", euid=euid)

    if syscall != EXPECTED_SYSCALL:
        return reject("unexpected_syscall", syscall=syscall)

    if success != EXPECTED_SUCCESS:
        return reject("execution_not_successful", success=success)

    if not isinstance(target, str) or not target:
        return reject("missing_target")

    if "\x00" in target:
        return reject("nul_in_target")

    if not os.path.isabs(target):
        return reject("target_not_absolute", target=target)

    normalized = os.path.normpath(target)

    if normalized != target:
        return reject("target_not_normalized", target=target)

    if os.path.dirname(target) != ALLOWED_ROOT:
        return reject("target_not_direct_child", target=target)

    try:
        expected_inode = int(alert_inode)
    except (TypeError, ValueError):
        return reject("invalid_alert_inode", target=target)

    try:
        expected_mode = int(str(alert_mode), 8)
    except (TypeError, ValueError):
        return reject("invalid_alert_mode", target=target)

    if not expected_mode & stat.S_ISUID:
        return reject(
            "alert_does_not_show_suid",
            target=target,
            alert_mode=alert_mode
        )

    try:
        lst = os.lstat(target)
    except FileNotFoundError:
        return reject("target_missing", target=target)
    except OSError as exc:
        return reject(
            "lstat_failed",
            target=target,
            error=type(exc).__name__
        )

    if stat.S_ISLNK(lst.st_mode):
        return reject("target_is_symlink", target=target)

    if not stat.S_ISREG(lst.st_mode):
        return reject("target_not_regular", target=target)

    if lst.st_uid != 0:
        return reject(
            "target_not_root_owned",
            target=target,
            uid=lst.st_uid
        )

    if lst.st_ino != expected_inode:
        return reject(
            "inode_changed_before_open",
            target=target,
            alert_inode=expected_inode,
            current_inode=lst.st_ino
        )

    flags = os.O_RDONLY | os.O_CLOEXEC

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(target, flags)
    except OSError as exc:
        return reject(
            "open_failed",
            target=target,
            error=type(exc).__name__
        )

    try:
        current = os.fstat(fd)

        if current.st_ino != expected_inode:
            return reject(
                "inode_changed_after_open",
                target=target,
                alert_inode=expected_inode,
                current_inode=current.st_ino
            )

        if not stat.S_ISREG(current.st_mode):
            return reject("opened_object_not_regular", target=target)

        if current.st_uid != 0:
            return reject(
                "opened_object_not_root_owned",
                target=target,
                uid=current.st_uid
            )

        if not current.st_mode & stat.S_ISUID:
            log(
                "NO_CHANGE",
                rule_id=rule_id,
                event_id=event_id,
                target=target,
                inode=current.st_ino,
                reason="suid_already_removed"
            )
            return 0

        before = stat.S_IMODE(current.st_mode)
        requested_after = before & ~stat.S_ISUID

        os.fchmod(fd, requested_after)

        verified = os.fstat(fd)
        after = stat.S_IMODE(verified.st_mode)

        if after & stat.S_ISUID:
            return reject(
                "suid_removal_verification_failed",
                target=target,
                mode_before=f"{before:04o}",
                mode_after=f"{after:04o}"
            )

        path_after = os.lstat(target)

        if path_after.st_ino != expected_inode:
            return reject(
                "path_changed_during_response",
                target=target,
                expected_inode=expected_inode,
                current_inode=path_after.st_ino
            )

        log(
            "SUCCESS",
            rule_id=rule_id,
            event_id=event_id,
            target=target,
            inode=expected_inode,
            mode_before=f"{before:04o}",
            mode_after=f"{after:04o}",
            action="removed_suid"
        )

        return 0

    except OSError as exc:
        return reject(
            "filesystem_operation_failed",
            target=target,
            error=type(exc).__name__
        )

    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
