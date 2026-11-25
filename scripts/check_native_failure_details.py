"""必要错误出口的纯内存断言；不读取日志、运行编译或调用网络。"""
from types import SimpleNamespace
from unittest.mock import patch

from ci_contract import require
from native_failure_details import (MAX_LOG, MAX_OUTPUT, PREFIX, emit_native_failure_details,
                                    parse_native_details)


def _parsing_cases():
    import json
    compile_error = b"/synthetic/source/Tests/sample.c:12:3: error: unknown type name 'sample'\n"
    value = parse_native_details(compile_error)
    require(value["available"] and value["last_case"] is None and value["errors"][0] ==
            {"kind": "compiler-error", "file": "Tests/sample.c", "line": 12, "column": 3,
             "message": "unknown type name 'sample'"}, "编译错误投影或未记录编号不符")
    assertion = b"Assertion failed: (value == 1), function exercise, file Tests/sample.c, line 15.\n"
    value = parse_native_details(b"WXA_NATIVE_CASE_V1 214 0\nWXA_NATIVE_CASE_V1 214 23\n" + assertion)
    require(value["last_case"] == 23 and value["errors"][0]["kind"] == "c-assertion" and
            "failed_case" not in value, "最近用例编号不能伪装成已证实的失败点")
    python = b'  File "/synthetic/source/Tests/sample.py", line 8, in main\nAssertionError: synthetic-private\n'
    value = parse_native_details(python)
    require([row["kind"] for row in value["errors"]] == ["python-location", "python-exception"] and
            "synthetic-private" not in json.dumps(value), "Python只允许位置及固定类别")
    value = parse_native_details(b"ordinary-private-noise\n")
    require(not value["available"] and value["errors"] == [], "未知格式不能回退原始日志")
    value = parse_native_details(b"Tests/sample.c:1: error: see https://synthetic.invalid/download?value=1\n")
    require("https://" not in json.dumps(value), "必要错误不能包含临时下载地址")
    invalid = [None, b"x" * (MAX_LOG + 1), b"\xff", compile_error * 17,
        b"WXA_NATIVE_CASE_V1 214 24\n", b"WXA_NATIVE_CASE_V1 214 -1\n",
        b"WXA_NATIVE_CASE_V1 214 1 extra\n", b"WXA_NATIVE_CASE_V1 213 1\n",
        b"../outside.c:1: error: synthetic\n", b"Tests/sample.c:1: error: token=synthetic-private\n",
        b"Tests/sample.c:1: error: " + b"x" * 1025 + b"\n",
        (b"Tests/sample.c:1: error: " + b"x" * 1000 + b"\n") * 16]
    for raw in invalid:
        try:
            parse_native_details(raw)
        except (ValueError, UnicodeError):
            continue
        raise ValueError("必要错误输入拒绝未生效")
    return 5 + len(invalid)


def _emission_cases():
    import json
    progress = SimpleNamespace(stage=214, exit_code=1)
    sample = b"Tests/sample.c:1: error: synthetic\n"
    with patch("native_failure_details._read_fixed_log", return_value=sample) as read, \
            patch("native_failure_details.print") as output:
        emit_native_failure_details(progress, "research", True, "synthetic-fixed-log")
        read.assert_called_once_with("synthetic-fixed-log")
        output.assert_called_once()
        line = output.call_args.args[0]
        require(line.startswith(PREFIX) and len((line + "\n").encode("ascii")) <= MAX_OUTPUT and
                json.loads(line[len(PREFIX):])["available"], "必要错误单次有界输出不符")
    rejected = [(214, 1, "offline", True), (213, 1, "research", True), (214, 0, "research", True),
                (214, True, "research", True), (True, 1, "research", True), (214, 1, "research", False),
                (214, 1, "research", 1)]
    for stage, code, kind, enabled in rejected:
        with patch("native_failure_details._read_fixed_log") as read, patch("native_failure_details.print") as output:
            emit_native_failure_details(SimpleNamespace(stage=stage, exit_code=code), kind, enabled, "synthetic")
            require(not read.called and not output.called, "默认、未知及非214阶段不能开启新出口")
    with patch("native_failure_details._read_fixed_log", side_effect=RuntimeError("synthetic-private")), \
            patch("native_failure_details.print") as output:
        emit_native_failure_details(progress, "research", True, "synthetic")
        text = output.call_args.args[0]
        require(json.loads(text[len(PREFIX):])["reason"] == "unavailable" and
                "synthetic-private" not in text, "读取异常不能泄漏或覆盖原失败")
    with patch("native_failure_details._read_fixed_log", return_value=sample), \
            patch("native_failure_details.print", side_effect=OSError("synthetic-private")):
        emit_native_failure_details(progress, "research", True, "synthetic")
    return 3 + len(rejected)


def _wiring(root):
    build = (root / "scripts/run_build.py").read_text()
    module = (root / "scripts/native_failure_details.py").read_text()
    call = 'emit_native_failure_details(progress, kind, diagnostic, private / "build.log")'
    require(build.count(call) == 1 and call + "\n        collect_failure(" in build and
            build.index(call) < build.index("    progress.enter(4)"), "必要错误只能接到原生失败分支")
    require('stdout=log, stderr=subprocess.STDOUT' in build and
            'raise SystemExit("构建或交付未完成；不上传原始日志，不自动重跑。") from None' in build,
            "新出口不能更改原重定向、失败或停止行为")
    require("os.O_NOFOLLOW | os.O_NONBLOCK" in module and "stream.read(MAX_LOG + 1)" in module and
            "before.st_mtime_ns" in module and "stat.S_IMODE(before.st_mode) == 0o600" in module and
            module.count("print(") == 1 and "subprocess" not in module,
            "固定日志读取及唯一输出必须有界，不执行外部工具")
    return 3


def check_native_failure_details(root):
    return _parsing_cases() + _emission_cases() + _wiring(root)
