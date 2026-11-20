"""公开加密交付的纯数据与文本契约，不下载、不执行 age。"""
import ast
import json
import subprocess
import urllib.error
from unittest.mock import patch

from ci_contract import (RESEARCH_CIPHER, RESEARCH_ENVELOPE, ROOT, require, unique_object,
                         upload_files)
from research_encryption import (ASSET_SHA256, ASSET_SIZE, ASSET_URL, TOOL_HASHES, VERSION,
                                 configured_recipient, parse_recipient_config)


def check_tool_preparation_failure():
    """只用虚构异常验证单行输出，不联网、不执行工具或读取真实诊断。"""
    from run_build import BuildProgress, tool_preparation_failure

    class UnreadableError(Exception):
        def __str__(self):
            raise AssertionError("非工具准备阶段不得读取异常原文")

    progress = BuildProgress()
    stages = (0, 1, 7, 9, 130, True, "8")
    for stage in stages:
        progress.stage = stage
        require(tool_preparation_failure(progress, UnreadableError()) is None,
                "其他阶段不能输出或读取异常")
    progress.enter(8)
    prefix = "研究工具准备失败："
    cases = [
        (ValueError("synthetic archive digest mismatch"), "synthetic archive digest mismatch"),
        (urllib.error.HTTPError("https://example.invalid/tool?signature=synthetic", 503,
                               "Service Unavailable", None, None), "HTTP Error 503: Service Unavailable"),
        (urllib.error.URLError("synthetic TLS verification failed"),
         "<urlopen error synthetic TLS verification failed>"),
        (OSError(13, "synthetic permission denied", "synthetic-tool"),
         "[Errno 13] synthetic permission denied: 'synthetic-tool'"),
        (subprocess.TimeoutExpired(["synthetic-tool", "--version"], 10,
                                   output=b"synthetic-output-not-for-display"),
         "Command '['synthetic-tool', '--version']' timed out after 10 seconds"),
        (ValueError("prefix HTTPS://example.invalid/tool?signature=synthetic#fragment suffix\n::error::synthetic"),
         "prefix <下载地址已省略> suffix\n::error::synthetic"),
        (ValueError("x" * 2048), "x" * 1024),
    ]
    for error, expected in cases:
        detail = tool_preparation_failure(progress, error)
        require(detail.startswith(prefix) and "\n" not in detail and "\r" not in detail and
                len(detail.encode("utf-8")) < 8 * 1024, "错误说明必须是有界单行")
        value = json.loads(detail[len(prefix):])
        require(value == {"exception": type(error).__name__, "message": expected} and
                "signature=synthetic" not in detail and "synthetic-output-not-for-display" not in detail,
                "必要错误被改变或输出了下载链接及工具输出")
    return len(stages) + len(cases)


def check_research_encryption():
    require(check_tool_preparation_failure() == 14, "工具准备错误纯内存场景未完整运行")
    config = ROOT / "config/research-recipient.json"
    value = json.loads(config.read_text(), object_pairs_hook=unique_object)
    selected = parse_recipient_config(value)
    require(parse_recipient_config({"schema": 1, "recipient": None}) is None, "未配置公钥不得暗设收件人")
    recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
    require(parse_recipient_config({"schema": 1, "recipient": recipient}) == recipient, "单公钥配置正向失败")
    cases = [lambda: parse_recipient_config({"schema": True, "recipient": None}),
             lambda: parse_recipient_config({"schema": 1, "recipient": "invalid"}),
             lambda: parse_recipient_config({"schema": 1, "recipient": [recipient]}),
             lambda: parse_recipient_config({"schema": 1, "recipient": recipient, "password": "synthetic"})]
    for case in cases:
        try:
            case()
        except ValueError:
            continue
        raise ValueError("研究公钥配置拒绝断言未生效")
    with patch("research_encryption.parse_recipient_config", return_value=None):
        try:
            configured_recipient()
        except ValueError:
            pass
        else:
            raise ValueError("空公钥未阻止研究发布")
    build = (ROOT / "scripts/run_build.py").read_text()
    crypto = (ROOT / "scripts/research_encryption.py").read_text()
    contract = (ROOT / "scripts/ci_contract.py").read_text()
    ast.parse(crypto)
    require(build.index('recipient = configured_recipient()') < build.index('"scripts/ci-build.sh"') and
            'if kind == "research":\n        tools = prepare_tools(' in build and
            'Tests/ResearchDeliveryEncryptionTests.py' in build and 'seal_research(payload, delivery, tools, recipient)' in build,
            "研究必须先核公钥，再完整构建和合成，离线不得下载工具")
    require(VERSION == "v1.3.2" and ASSET_SIZE == 19376787 and ASSET_URL.endswith("/v1.3.2/age-v1.3.2-darwin-amd64.tar.gz") and
            ASSET_SHA256 == "1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539" and
            set(TOOL_HASHES) == {"age", "age-keygen", "age-plugin-batchpass"}, "工具必须固定版本和归档身份")
    require(upload_files("research") == (RESEARCH_CIPHER, RESEARCH_ENVELOPE) and
            "urllib.request.urlopen(ASSET_URL, timeout=25)" in crypto and
            '"-e", "-r", recipient' in crypto and 'validate_research_manifest(manifest, source_sha, ci)' in crypto and
            'inspect_research_payload(payload / expected["archive"], role, manifest["roles"][role])' in crypto and
            'inspect_research_payload(build / expected["archive"], key, identity["roles"][key])' in contract and
            'sum(item["size"] for item in files) <= 2 * MAX_FILE' in contract,
            "公开端只接公钥并核实内层，不得读取解密材料")
    strings = {node.value for node in ast.walk(ast.parse(crypto)) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    require("passphrase.txt" not in strings and "identity.age" not in strings and
            "AGE_PASSPHRASE" not in strings and "AGE_PASSPHRASE_FD" not in strings,
            "公开封套模块不得接触真实解密凭据")
    return len(cases) + 1, selected is not None
