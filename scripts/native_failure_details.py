"""仅为显式研究阶段214失败输出有界必要错误，不转储原始日志。"""
import json
import os
import re
import stat

PREFIX = "WXA_NATIVE_ERROR_V1 "
MAX_LOG = 8 * 1024 * 1024
MAX_OUTPUT = 8 * 1024
MAX_RECORDS = 16
CASE = re.compile(r"WXA_NATIVE_CASE_V1 214 ([0-9]{1,2})")
COMPILER = re.compile(r"(.+?\.(?:c|h|m|mm|swift)):([1-9][0-9]{0,6})(?::([1-9][0-9]{0,5}))?: (?:fatal )?error: (.+)")
ASSERTION = re.compile(r"Assertion failed: \((.+)\), function [^,\r\n]+, file (.+\.(?:c|h|m|mm)), line ([1-9][0-9]{0,6})\.")
PYTHON = re.compile(r'\s*File "([^"]+\.py)", line ([1-9][0-9]{0,6}), in [A-Za-z_<>][A-Za-z_0-9.<>]*')
PYTHON_ERRORS = frozenset(("AssertionError", "ValueError", "TypeError", "RuntimeError", "OSError",
                          "TimeoutError", "PermissionError"))
CHILD_MARKER = "RuntimeError: WXA_SYNTHETIC_CHILD_V1"
CHILD = re.compile(r"RuntimeError: WXA_SYNTHETIC_CHILD_V1 ([0-2]) (-?[1-9][0-9]{0,2}) "
                   r"(empty|firstline|oversize|nontext|sensitive) (.+)")
SENSITIVE = re.compile(r"gh[pousr]_|github_pat_|AGE-SECRET-KEY-|authorization\s*:|bearer\s+\S+|"
                       r"(?:token|passphrase|password|private[_ -]?key)\s*[=:]", re.IGNORECASE)


def _source_file(value):
    parts = value.split("/")
    if ".." in parts or SENSITIVE.search(value):
        raise ValueError("不允许的错误位置")
    if not all(not part or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", part) for part in parts):
        raise ValueError("错误位置格式未知")
    for index, part in enumerate(parts):
        if part in ("Tests", "Reader", "Core", "App", "scripts"):
            return "/".join(parts[index:])
    return parts[-1]


def _message(value):
    value = re.sub(r"https?://\S+", "<地址已省略>", value, flags=re.IGNORECASE)
    if not value or len(value.encode("utf-8")) > 1024 or not value.isprintable() or SENSITIVE.search(value):
        raise ValueError("必要错误不可公开")
    return value


def _child_exit(line):
    match = CHILD.fullmatch(line)
    if not match or not -127 <= int(match[2]) <= 255:
        raise ValueError("合成退出消息字段无效")
    case, code, state, detail = match[1], int(match[2]), match[3], match[4]
    if state == "firstline":
        if not (0 < len(detail.encode("utf-8")) <= 512 and detail.isprintable() and
                not detail.isspace() and not SENSITIVE.search(detail)):
            raise ValueError("必要首行不可公开")
        detail = re.sub(r"https?://\S+", "<URL>", detail, flags=re.IGNORECASE)
    elif detail != "-":
        raise ValueError("分类消息不得夹带错误内容")
    return _message(f"{CHILD_MARKER} {case} {code} {state} {detail}")


def _record(line, allow_child=False):
    if match := COMPILER.fullmatch(line):
        return {"kind": "compiler-error", "file": _source_file(match[1]), "line": int(match[2]),
                "column": int(match[3]) if match[3] else None, "message": _message(match[4])}
    if match := ASSERTION.fullmatch(line):
        return {"kind": "c-assertion", "file": _source_file(match[2]), "line": int(match[3]),
                "column": None, "message": _message(match[1])}
    if match := PYTHON.fullmatch(line):
        return {"kind": "python-location", "file": _source_file(match[1]), "line": int(match[2]),
                "column": None, "message": None}
    if line.startswith(CHILD_MARKER):
        if not allow_child:
            raise ValueError("合成退出消息缺少测试回溯上下文")
        return {"kind": "python-exception", "file": None, "line": None, "column": None,
                "message": _child_exit(line)}
    name = line.split(":", 1)[0]
    if name in PYTHON_ERRORS:
        return {"kind": "python-exception", "file": None, "line": None, "column": None, "message": name}
    return None


def _empty(reason):
    return {"schema": 1, "stage": 214, "available": False, "reason": reason, "last_case": None, "errors": []}


def _encode(value):
    return PREFIX + json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def parse_native_details(raw):
    """只提取限定格式；最近用例编号不等于已证实的失败用例。"""
    if type(raw) is not bytes or len(raw) > MAX_LOG:
        raise ValueError("必要错误输入超限或类型未知")
    result = _empty("no_match")
    last_python_file = None
    for line in raw.decode("utf-8").splitlines():
        if line == "Traceback (most recent call last):":
            last_python_file = None
            continue
        if line.startswith("WXA_NATIVE_CASE_V1"):
            match = CASE.fullmatch(line)
            if not match or int(match[1]) > 23:
                raise ValueError("合成用例编号无效")
            result["last_case"] = int(match[1])
            continue
        record = _record(line, bool(last_python_file and last_python_file.startswith("Tests/")))
        if record is not None:
            result["errors"].append(record)
            last_python_file = record["file"] if record["kind"] == "python-location" else None
            if len(result["errors"]) > MAX_RECORDS:
                raise ValueError("必要错误条数超限")
    if result["errors"]:
        result["available"], result["reason"] = True, "matched"
    if len((_encode(result) + "\n").encode("ascii")) > MAX_OUTPUT:
        raise ValueError("必要错误输出超限")
    return result


def _read_fixed_log(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1 and
                stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= MAX_LOG):
            raise ValueError("固定原生日志条件不符")
        raw = stream.read(MAX_LOG + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("固定原生日志已变化")
        return raw


def emit_native_failure_details(progress, kind, enabled, path):
    """详情不可用也不覆盖调用者正在抛出的原始失败，不重试或追加其他日志。"""
    if (kind != "research" or enabled is not True or type(progress.stage) is not int or progress.stage != 214 or
            type(progress.exit_code) is not int or progress.exit_code == 0):
        return
    try:
        details = parse_native_details(_read_fixed_log(path))
    except Exception:
        details = _empty("unavailable")
    try:
        print(_encode(details), flush=True)
    except Exception:
        # 控制台不可用不能改变原构建失败或触发替代出口。
        pass
