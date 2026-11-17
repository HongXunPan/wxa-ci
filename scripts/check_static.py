"""仅解析公开外壳、固定工作流及内存归档边界，不取源码、不编译。"""
import ast
import copy
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from unittest.mock import patch

from ci_contract import (FILES, RESEARCH_ROLES, ROOT, delivery_files, delivery_kind,
                         inspect_research_archive, require, unique_object, upload_files, validate_research_identity)
from check_research_encryption import check_research_encryption
from check_synthetic_query_report import check_synthetic_query_report
from fetch_source import source_members

CHECKOUT = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
UPLOAD = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"


def check_workflow():
    path = ROOT / ".github/workflows/macos.yml"
    require({item.name for item in path.parent.iterdir() if item.suffix in (".yml", ".yaml")} == {path.name},
            "不能增加未经确认的其他公开工作流")
    parsed = subprocess.run(["/usr/bin/ruby", "-rjson", "-ryaml", "-e",
        "print JSON.generate(YAML.safe_load(File.read(ARGV.fetch(0))))", str(path)],
        capture_output=True, text=True, timeout=10)
    require(parsed.returncode == 0, "公开工作流 YAML 无效")
    value = json.loads(parsed.stdout)
    require(set(value["on"]) == {"workflow_dispatch"} and
            value["permissions"] == {"contents": "read"} and set(value["jobs"]) == {"intel"}, "触发或权限范围不符")
    inputs = value["on"]["workflow_dispatch"]["inputs"]
    require(set(inputs) == {"source_sha", "delivery_kind"} and inputs["source_sha"]["required"] is True and
            inputs["source_sha"]["type"] == "string", "不能接受任意仓库或命令输入")
    require(inputs["delivery_kind"]["required"] is True and inputs["delivery_kind"]["type"] == "choice" and
            inputs["delivery_kind"]["default"] == "offline" and
            inputs["delivery_kind"]["options"] == ["offline", "research"], "研究交付必须是显式固定档位")
    require(value["run-name"] == "受控构建 · ${{ inputs.delivery_kind }} · ${{ inputs.source_sha }}", "运行身份展示不符")
    job = value["jobs"]["intel"]
    require(job["if"] == "github.repository == 'HongXunPan/wxa-ci' && github.ref == 'refs/heads/main' && github.actor == github.repository_owner" and
            job["runs-on"] == "macos-15-intel" and job["timeout-minutes"] == 20, "执行身份或期限不符")
    require(job["env"] == {"DEVELOPER_DIR": "/Applications/Xcode_16.4.app/Contents/Developer",
            "PYTHONDONTWRITEBYTECODE": "1", "WXA_SOURCE_SHA": "${{ inputs.source_sha }}"}, "工具链或输入传递不符")
    steps = job["steps"]
    require(len(steps) == 6 and steps[0]["uses"] == CHECKOUT and
            steps[0]["with"] == {"persist-credentials": False}, "公开外壳检出不符")
    for step, script in zip(steps[1:4], ("check_static.py", "fetch_source.py", "run_build.py")):
        require(step["run"] == "/usr/bin/python3 scripts/" + script and
                not step.get("continue-on-error") and not step.get("if"), "受控执行入口或失败行为不符")
    require(steps[2]["env"] == {"WXA_SOURCE_READ_TOKEN": "${{ secrets.WXA_SOURCE_READ_TOKEN }}"} and
            steps[3]["env"] == {"WXA_DELIVERY_KIND": "${{ inputs.delivery_kind }}"} and
            all("env" not in steps[index] for index in (0, 1, 4, 5)) and
            path.read_text().count("secrets.") == 1, "凭证只能交给源码获取步骤")
    for index, kind in ((4, "offline"), (5, "research")):
        require(steps[index]["uses"] == UPLOAD and steps[index]["with"] == {
            "name": "wxa-delivery-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": "".join(".codex-tmp/delivery/" + name + "\n" for name in upload_files(kind)),
            "archive": True, "include-hidden-files": True,
            "if-no-files-found": "error", "retention-days": 1, "compression-level": 0} and
            steps[index].get("if") == "${{ inputs.delivery_kind == '" + kind + "' }}" and
            not steps[index].get("continue-on-error"), "只能在成功后按显式档位上传一个固定附件")


def check_archive_boundaries():
    def member(name, kind=tarfile.REGTYPE, size=1):
        result = tarfile.TarInfo(name)
        result.type, result.size = kind, size
        return result

    require(str(source_members([member("root/synthetic.swift")])[0][0]) == "synthetic.swift", "合成归档正向断言失败")
    cases = [[member("../outside")], [member("/absolute")], [member("root/.git/config")],
             [member("root/link", tarfile.SYMTYPE)], [member("root/link", tarfile.LNKTYPE)],
             [member("root/file"), member("root/file")], [member("root/file"), member("other/file")],
             [member("root/file", size=8 * 1024 * 1024 + 1)]]
    for case in cases:
        try:
            source_members(case)
        except ValueError:
            continue
        raise ValueError("源码归档拒绝断言未生效")
    return len(cases)


def research_archive_fixture(role, name=None, member_type=tarfile.REGTYPE, extra=False):
    content = b"synthetic-research-payload"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        item = tarfile.TarInfo(name or role["name"])
        item.type, item.size = member_type, len(content)
        archive.addfile(item, io.BytesIO(content) if member_type == tarfile.REGTYPE else None)
        if extra:
            archive.addfile(tarfile.TarInfo("build.log"))
    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode="r:") as archive:
        inspect_research_archive(archive, role)


def check_research_boundaries():
    content = b"synthetic-research-payload"
    value = {"schema": 1, "roles": {key: {
        "name": role["name"], "identifier": role["identifier"], "architecture": "x86_64", "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(), "cdhash": ("c" if key == "research" else "d") * 40,
        "hardened_runtime": True, "disable_library_validation": role["disable_library_validation"]}
        for key, role in RESEARCH_ROLES.items()},
        "bindings": {"app_cdhash": "e" * 40, "research_cdhash": "c" * 40}}
    require(validate_research_identity(value) == value, "研究身份正向断言失败")
    for role in value["roles"].values():
        research_archive_fixture(role)
    mutations = [(('roles', 'other'), {}), (('roles', 'reader', 'name'), 'WeChatAssistantResearch'),
        (('roles', 'reader', 'identifier'), 'synthetic.invalid'), (('roles', 'reader', 'size'), True),
        (('roles', 'reader', 'architecture'), 'arm64'), (('roles', 'research', 'cdhash'), 'c' * 39),
        (('roles', 'reader', 'sha256'), 'z' * 64), (('roles', 'reader', 'hardened_runtime'), 1),
        (('roles', 'reader', 'disable_library_validation'), False), (('bindings', 'app_cdhash'), 'e' * 39),
        (('bindings', 'research_cdhash'), 'e' * 40), (('raw_log',), 'synthetic')]
    for path, replacement in mutations:
        changed = copy.deepcopy(value)
        parent = changed
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = replacement
        try:
            validate_research_identity(changed)
        except ValueError:
            continue
        raise ValueError("研究身份拒绝断言未生效")
    role = value["roles"]["research"]
    checks = [lambda: research_archive_fixture(role, "../outside"),
        lambda: research_archive_fixture(role, member_type=tarfile.SYMTYPE),
        lambda: research_archive_fixture(role, extra=True),
        lambda: research_archive_fixture(dict(role, sha256="0" * 64)),
        lambda: delivery_files("latest"), lambda: unique_object([("schema", 1), ("schema", 2)])]
    for check in checks:
        try:
            check()
        except ValueError:
            continue
        raise ValueError("研究归档或档位拒绝断言未生效")
    with patch.dict(os.environ, {}, clear=True):
        require(delivery_kind() == "offline", "默认交付不能变为研究")
    with patch.dict(os.environ, {"WXA_DELIVERY_KIND": "research"}):
        require(delivery_kind() == "research", "显式研究档位未传递")
    return len(mutations) + len(checks)


def main():
    check_workflow()
    require(set(FILES) == {"WeChatAssistant-demo-macos-x86_64.zip", "WCDBSyntheticProbe-macos-x86_64.tgz",
                           "LiveFilesGuardProbe-macos-x86_64.tgz"}, "交付白名单不符")
    require(not any(path.name.casefold() == "agents.md" for path in ROOT.iterdir()), "公开根目录不能保留协作规则文件")
    paths = [ROOT / name for name in ("README.md", ".gitignore", ".github/workflows/macos.yml", "config/research-recipient.json")]
    paths.extend(sorted((ROOT / "scripts").glob("*.py")))
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "公开资产缺失或为链接")
        text = path.read_text()
        require(text.endswith("\n") and not any(line.rstrip() != line for line in text.splitlines()) and
                "\r" not in text and "\x00" not in text, "公开文本格式不符")
        require("/" + "Users" + "/" not in text and not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", text),
                "公开资产包含个人路径或凭证模式")
        if path.suffix == ".py":
            ast.parse(text)
    build = (ROOT / "scripts/run_build.py").read_text()
    require("stdout=log, stderr=subprocess.STDOUT" in build and "GITHUB_STEP_SUMMARY" not in build and
            'require(not os.environ.get("WXA_SOURCE_READ_TOKEN")' in build and
            '"scripts/check_static.py"' in build and '"scripts/ci-build.sh"' in build, "构建隔离或完整门禁缺失")
    require('for name in delivery_files(kind)' in build and 'manifest.update(research_fields(build))' in build and
            'if kind == "research":' in build and 'WXA_DELIVERY_KIND=kind' in build and
            set(delivery_files("research")) == {"WeChatAssistantResearch-macos-x86_64.tgz", "SourceReaderCandidate-macos-x86_64.tgz"},
            "研究配套必须共用完整构建并独立验证身份与归档，不混入离线包")
    cases = check_archive_boundaries()
    research_cases = check_research_boundaries()
    encryption_cases, configured = check_research_encryption()
    synthetic_cases = check_synthetic_query_report(ROOT)
    print(json.dumps({"阶段": "公开外壳轻量静态检查", "通过": True, "检查文件数": len(paths),
                      "归档纯内存拒绝场景数": cases, "研究交付纯内存拒绝场景数": research_cases,
                      "加密配置拒绝场景数": encryption_cases, "研究公钥已配置": configured, "合成统计拒绝场景数": synthetic_cases,
                      "读取私有源码": False, "执行编译": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("公开外壳静态检查失败；不打印私有信息，不执行构建。", file=sys.stderr)
        raise SystemExit(2)
