"""公开加密交付的纯数据与文本契约，不下载、不执行 age。"""
import ast
import json
from unittest.mock import patch

from ci_contract import (RESEARCH_CIPHER, RESEARCH_ENVELOPE, ROOT, require, unique_object,
                         upload_files)
from research_encryption import (ASSET_SHA256, ASSET_SIZE, ASSET_URL, TOOL_HASHES, VERSION,
                                 configured_recipient, parse_recipient_config)


def check_research_encryption():
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
            'inspect_research_archive(archive, manifest["roles"][role])' in crypto,
            "公开端只接公钥并核实内层，不得读取解密材料")
    strings = {node.value for node in ast.walk(ast.parse(crypto)) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    require("passphrase.txt" not in strings and "identity.age" not in strings and
            "AGE_PASSPHRASE" not in strings and "AGE_PASSPHRASE_FD" not in strings,
            "公开封套模块不得接触真实解密凭据")
    return len(cases) + 1, selected is not None
