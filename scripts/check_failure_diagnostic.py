"""失败诊断的纯内存开关及停止行为断言；不运行工具或读取日志。"""
import ast
import os
from unittest.mock import patch

import failure_diagnostic
from ci_contract import ROOT, require
from failure_diagnostic import CIPHER, ENVELOPE, MAX_CIPHER, MAX_PLAIN, collect_failure, diagnostic_requested


def check_failure_diagnostic():
    from run_build import BuildProgress

    with patch.dict(os.environ, {}, clear=True):
        require(not diagnostic_requested("offline") and not diagnostic_requested("research"), "诊断必须默认关闭")
    with patch.dict(os.environ, {"WXA_FAILURE_DIAGNOSTIC": "true"}, clear=True):
        require(diagnostic_requested("research"), "研究诊断显式开关失效")
        try:
            diagnostic_requested("offline")
        except ValueError:
            pass
        else:
            raise ValueError("离线档位不应启用失败诊断")
    for value in ("1", "TRUE", "", "synthetic-private"):
        with patch.dict(os.environ, {"WXA_FAILURE_DIAGNOSTIC": value}, clear=True):
            try:
                diagnostic_requested("research")
            except ValueError:
                continue
            raise ValueError("未知诊断开关未拒绝")
    for enabled, stage, code, error in ((False, 130, 120, None), (True, 203, 1, None),
            (True, 130, 0, None), (True, 130, 120, None), (True, 130, 120, ValueError("synthetic-private"))):
        progress = BuildProgress()
        progress.stage, progress.exit_code = stage, code
        original = progress.failure_frame()
        with patch.object(failure_diagnostic, "publish_failure", side_effect=error) as publish:
            result = collect_failure(progress, enabled, "synthetic-source", "synthetic-private", "synthetic-recipient")
            expected = enabled and stage == 130 and code != 0
            require(publish.call_count == int(expected) and result == (expected and error is None), "诊断路径越界或发生重试")
        require(progress.failure_frame() == original, "诊断不能覆盖原构建失败")
    text = (ROOT / "scripts/failure_diagnostic.py").read_text()
    tree = ast.parse(text)
    strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    require(not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"
                    for node in ast.walk(tree)) and "passphrase.txt" not in strings and "identity.age" not in strings,
            "公开诊断不得打印原文或读取私钥材料")
    require('source / "build/test.log"' in text and 'prepare_tools(private / "failure-age-tools")' in text and
            'input=data' in text and 'diagnostic_ready=true\\n' in text and 'if not complete:' in text and
            'os.O_NOFOLLOW' in text and 'st_mtime_ns' in strings and 'st_atime_ns' not in strings and
            MAX_PLAIN == 8 * 1024 * 1024 and MAX_CIPHER == MAX_PLAIN + 64 * 1024 and
            (CIPHER, ENVELOPE) == ("xctest.log.age", "diagnostic-envelope.json"), "诊断范围、预算或清理不符")
    build = (ROOT / "scripts/run_build.py").read_text()
    require('diagnostic = diagnostic_requested(kind)' in build and
            'collect_failure(progress, diagnostic, source, private, recipient)\n        raise' in build,
            "诊断结束后必须继续抛出原始构建失败")
    return 13
