"""仅解析公开外壳、固定工作流及内存归档边界，不取源码、不编译。"""
import ast
import copy
import hashlib
import io
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from unittest.mock import patch

from ci_contract import (FILES, MAX_FILE, RESEARCH_ROLES, ROOT, delivery_files, delivery_kind,
                         inspect_app_archive, inspect_research_archive, require, unique_object, upload_files, validate_research_identity)
from check_research_encryption import check_research_encryption
from check_synthetic_query_report import check_synthetic_query_report
from check_failure_diagnostic import check_failure_diagnostic
from run_build import BuildProgress, NATIVE_STAGES, parse_native_stage
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
    require(set(inputs) == {"source_sha", "delivery_kind", "failure_diagnostic"} and inputs["source_sha"]["required"] is True and
            inputs["source_sha"]["type"] == "string", "不能接受任意仓库或命令输入")
    require(inputs["delivery_kind"]["required"] is True and inputs["delivery_kind"]["type"] == "choice" and
            inputs["delivery_kind"]["default"] == "offline" and
            inputs["delivery_kind"]["options"] == ["offline", "research"], "研究交付必须是显式固定档位")
    require(inputs["failure_diagnostic"]["required"] is True and inputs["failure_diagnostic"]["type"] == "boolean" and
            inputs["failure_diagnostic"]["default"] is False, "失败诊断必须显式开启且默认关闭")
    require(value["run-name"] == "受控构建 · ${{ inputs.delivery_kind }} · ${{ inputs.source_sha }}", "运行身份展示不符")
    job = value["jobs"]["intel"]
    require(job["if"] == "github.repository == 'HongXunPan/wxa-ci' && github.ref == 'refs/heads/main' && github.actor == github.repository_owner" and
            job["runs-on"] == "macos-15-intel" and job["timeout-minutes"] == 20, "执行身份或期限不符")
    require(job["env"] == {"DEVELOPER_DIR": "/Applications/Xcode_16.4.app/Contents/Developer",
            "PYTHONDONTWRITEBYTECODE": "1", "WXA_SOURCE_SHA": "${{ inputs.source_sha }}"}, "工具链或输入传递不符")
    steps = job["steps"]
    require(len(steps) == 7 and steps[0]["uses"] == CHECKOUT and
            steps[0]["with"] == {"persist-credentials": False}, "公开外壳检出不符")
    for step, script in zip(steps[1:4], ("check_static.py", "fetch_source.py", "run_build.py")):
        require(step["run"] == "/usr/bin/python3 scripts/" + script and
                not step.get("continue-on-error") and not step.get("if"), "受控执行入口或失败行为不符")
    require(steps[2]["env"] == {"WXA_SOURCE_READ_TOKEN": "${{ secrets.WXA_SOURCE_READ_TOKEN }}"} and
            steps[3].get("id") == "build" and steps[3]["env"] == {"WXA_DELIVERY_KIND": "${{ inputs.delivery_kind }}",
                "WXA_FAILURE_DIAGNOSTIC": "${{ inputs.failure_diagnostic }}"} and
            all("env" not in steps[index] for index in (0, 1, 4, 5, 6)) and
            path.read_text().count("secrets.") == 1, "凭证只能交给源码获取步骤")
    for index, kind in ((4, "offline"), (6, "research")):
        require(steps[index]["uses"] == UPLOAD and steps[index]["with"] == {
            "name": "wxa-delivery-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": "".join(".codex-tmp/delivery/" + name + "\n" for name in upload_files(kind)),
            "archive": True, "include-hidden-files": True,
            "if-no-files-found": "error", "retention-days": 1, "compression-level": 0} and
            steps[index].get("if") == "${{ inputs.delivery_kind == '" + kind + "' }}" and
            not steps[index].get("continue-on-error"), "只能在成功后按显式档位上传一个固定附件")
    require(steps[5]["uses"] == UPLOAD and steps[5].get("if") ==
            "${{ failure() && steps.build.outcome == 'failure' && inputs.delivery_kind == 'research' && inputs.failure_diagnostic && steps.build.outputs.diagnostic_ready == 'true' }}" and
            steps[5]["with"] == {"name": "wxa-failure-diagnostic-${{ github.run_id }}-${{ github.run_attempt }}",
                "path": ".codex-tmp/failure-diagnostic/xctest.log.age\n.codex-tmp/failure-diagnostic/diagnostic-envelope.json\n",
                "archive": True, "include-hidden-files": True, "if-no-files-found": "error",
                "retention-days": 1, "compression-level": 0} and not steps[5].get("continue-on-error"),
            "失败诊断只能独立上传固定密文与封套，不能转绿或上传明文")


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


def synthetic_app_archive(info=None, content=None):
    """只生成不可执行的虚构头和内存 ZIP，不使用真实 App 或个人数据。"""
    expected = RESEARCH_ROLES["app"]
    if content is None:
        content = b"".join(value.to_bytes(4, "little") for value in (0xfeedfacf, 0x1000007, 3, 2, 0, 0, 0, 0))
        content += b"synthetic-app-not-executed"
    role = {"name": expected["name"], "identifier": expected["identifier"], "architecture": "x86_64",
        "size": len(content), "sha256": hashlib.sha256(content).hexdigest(), "cdhash": "e" * 40,
        "hardened_runtime": True, "disable_library_validation": False}
    root = "WeChatAssistant.app/"
    files = {root + "Contents/MacOS/WeChatAssistant": content,
        root + "Contents/Info.plist": plistlib.dumps(info if info is not None else {
            "CFBundleIdentifier": expected["identifier"], "CFBundleExecutable": expected["name"], "CFBundlePackageType": "APPL"}),
        root + "Contents/PkgInfo": b"APPL????", root + "Contents/_CodeSignature/CodeResources": b"synthetic-resource-not-signed"}
    for name in ("WeChatAssistantDemoReader", "WeChatAssistantIPCCheck", "WeChatAssistantIPCWorker"):
        files[root + "Contents/MacOS/" + name] = b"synthetic-tool-not-executed"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in (root, root + "Contents/", root + "Contents/MacOS/", root + "Contents/_CodeSignature/"):
            item = zipfile.ZipInfo(name); item.external_attr = (stat.S_IFDIR | 0o755) << 16
            archive.writestr(item, b"")
        for name, data in files.items():
            item = zipfile.ZipInfo(name); item.external_attr = (stat.S_IFREG | 0o555) << 16
            archive.writestr(item, data)
    return buffer.getvalue(), role


def app_archive_cases(require):
    content, role = synthetic_app_archive()

    def inspect(data=content, value=role, mutate=None):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if mutate:
                mutate(archive)
            inspect_app_archive(archive, value)

    inspect()
    root = "WeChatAssistant.app/"
    main = root + "Contents/MacOS/WeChatAssistant"
    info = root + "Contents/Info.plist"
    tool = root + "Contents/MacOS/WeChatAssistantDemoReader"
    wrong_info, _ = synthetic_app_archive(info={"CFBundleIdentifier": "synthetic.invalid"})
    wrong_code, wrong_role = synthetic_app_archive(content=b"synthetic-not-macho")
    cases = [
        lambda: inspect(value=dict(role, sha256="0" * 64)),
        lambda: inspect(value=dict(role, size=role["size"] + 1)),
        lambda: inspect(data=wrong_info), lambda: inspect(data=wrong_code, value=wrong_role),
        lambda: inspect(mutate=lambda a: a.filelist.append(copy.copy(a.filelist[-1]))),
        lambda: inspect(mutate=lambda a: a.filelist.pop()),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(main), "filename", "../outside")),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(main), "external_attr", (stat.S_IFLNK | 0o777) << 16)),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(root), "file_size", 1)),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(info), "file_size", 16 * 1024 + 1)),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(main), "file_size", MAX_FILE + 1)),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(tool), "file_size", MAX_FILE)),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(main), "orig_filename", main + "\\0")),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(main), "flag_bits", 1)),
        lambda: inspect(mutate=lambda a: setattr(a.getinfo(main), "compress_type", zipfile.ZIP_BZIP2)),
    ]
    for case in cases:
        try:
            case()
        except ValueError:
            continue
        raise ValueError("App 内存归档拒绝断言未生效")
    return len(cases)


def check_research_boundaries():
    content = b"synthetic-research-payload"
    value = {"schema": 2, "roles": {key: {
        "name": role["name"], "identifier": role["identifier"], "architecture": "x86_64", "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(), "cdhash": ("c" if key == "research" else "d") * 40,
        "hardened_runtime": True, "disable_library_validation": role["disable_library_validation"]}
        for key, role in RESEARCH_ROLES.items()},
        "bindings": {"app_cdhash": "e" * 40, "research_cdhash": "c" * 40}}
    _, value["roles"]["app"] = synthetic_app_archive()
    require(validate_research_identity(value) == value, "研究身份正向断言失败")
    for key, role in value["roles"].items():
        if key != "app":
            research_archive_fixture(role)
    mutations = [(('roles', 'other'), {}), (('roles', 'reader', 'name'), 'WeChatAssistantResearch'),
        (('roles', 'reader', 'identifier'), 'synthetic.invalid'), (('roles', 'reader', 'size'), True),
        (('roles', 'reader', 'architecture'), 'arm64'), (('roles', 'research', 'cdhash'), 'c' * 39),
        (('roles', 'reader', 'sha256'), 'z' * 64), (('roles', 'reader', 'hardened_runtime'), 1),
        (('roles', 'reader', 'disable_library_validation'), False), (('bindings', 'app_cdhash'), 'e' * 39),
        (('bindings', 'research_cdhash'), 'e' * 40), (('raw_log',), 'synthetic'),
        (('schema',), 1), (('bindings', 'app_cdhash'), 'f' * 40),
        (('roles', 'app', 'identifier'), 'synthetic.invalid'), (('roles', 'app', 'disable_library_validation'), True)]
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
        lambda: delivery_files("latest"), lambda: unique_object([("schema", 1), ("schema", 2)]),
        lambda: validate_research_identity(dict(value, roles={key: role for key, role in value["roles"].items() if key != "app"}))]
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
    return len(mutations) + len(checks) + app_archive_cases(require)


def check_failure_stages():
    """纯内存校验固定元数据；子命令全部替身，不读取报告或执行工具。"""
    require(len(NATIVE_STAGES) == 87 and all(type(value) is int for value in NATIVE_STAGES),
            "原生阶段白名单不符")
    require(parse_native_stage(b"synthetic-private\nWXA_CI_STAGE_V1 300\nWXA_CI_STAGE_V1 308\n") == 308,
            "固定阶段正向断言失败")
    invalid = [b"", b"WXA_CI_STAGE_V1 308", b"WXA_CI_STAGE_V1 399\n",
        b"WXA_CI_STAGE_V2 308\n", b"WXA_CI_STAGE_V1 308 raw\n", b"WXA_CI_STAGE_V1 308\r\n",
        b"x" * (16 * 1024 + 1), b"WXA_CI_STAGE_V1 308\nWXA_CI_STAGE_V1 unknown\n"]
    require(all(parse_native_stage(value) == 3 for value in invalid), "固定阶段拒绝断言失败")
    progress = BuildProgress()
    for stage in sorted(NATIVE_STAGES | set(range(1, 12))):
        progress.enter(stage)
        require(progress.failure_frame() == f"WXA_CI_FAILURE_V1 {stage:03d} 0", "阶段编码不符")
    frames = [(True, 1, "000 1"), ("synthetic-private", 1, "000 1"), (308, True, "308 0"),
              (308, 256, "308 0"), (308, -128, "308 0"), (308, -6, "308 -6")]
    for stage, code, expected in frames:
        progress.stage, progress.exit_code = stage, code
        require(progress.failure_frame() == "WXA_CI_FAILURE_V1 " + expected, "编码泄漏未确认字段")
    failed = subprocess.CompletedProcess(["synthetic-tool"], 134)
    with patch("run_build.subprocess.run", return_value=failed) as invoked, patch("run_build.native_stage", return_value=308) as report:
        try:
            progress.run(3, ["synthetic-tool"], report="synthetic-report")
        except ValueError:
            pass
        else:
            raise ValueError("失败子命令未保留原门禁")
        invoked.assert_called_once()
        report.assert_called_once_with("synthetic-report")
    require(progress.failure_frame() == "WXA_CI_FAILURE_V1 308 134", "未保留固定子步骤退出码")
    with patch("run_build.subprocess.run", return_value=subprocess.CompletedProcess(["synthetic-tool"], 0)), patch("run_build.native_stage") as report:
        progress.run(3, ["synthetic-tool"], report="synthetic-report")
        require(not report.called and progress.failure_frame() == "WXA_CI_FAILURE_V1 003 0", "成功路径读取了失败报告")
    for error in (ValueError("synthetic-private"), subprocess.TimeoutExpired("synthetic-tool", 1)):
        with patch("run_build.subprocess.run", side_effect=error) as invoked:
            try:
                progress.run(2, ["synthetic-tool"])
            except (ValueError, subprocess.TimeoutExpired):
                pass
            else:
                raise ValueError("异常子命令未停止")
            invoked.assert_called_once()
        require(progress.failure_frame() == "WXA_CI_FAILURE_V1 002 0", "未知退出码不应伪造或公开异常")
    build = (ROOT / "scripts/run_build.py").read_text()
    require('source.read(16 * 1024 + 1)' in build and 'print(progress.failure_frame(), flush=True)' in build and
            'raise SystemExit("构建或交付未完成；不上传原始日志，不自动重跑。") from None' in build,
            "失败出口必须有界且保留原停止行为")
    outputs = [node for node in ast.walk(ast.parse(build)) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"]
    require(len(outputs) == 2 and all(isinstance(node.args[0], ast.Constant) or
            isinstance(node.args[0], ast.Call) and isinstance(node.args[0].func, ast.Attribute) and
            node.args[0].func.attr == "failure_frame" for node in outputs), "不能公开原始日志或异常")
    return len(invalid) + len(frames) + 4


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
            set(delivery_files("research")) == {"WeChatAssistant-demo-macos-x86_64.zip",
                "WeChatAssistantResearch-macos-x86_64.tgz", "SourceReaderCandidate-macos-x86_64.tgz"},
            "研究配套须含同次 App、研究端与读取器，不混入探针或其他候选")
    cases = check_archive_boundaries()
    research_cases = check_research_boundaries()
    encryption_cases, configured = check_research_encryption()
    synthetic_cases = check_synthetic_query_report(ROOT)
    failure_cases = check_failure_stages()
    diagnostic_cases = check_failure_diagnostic()
    print(json.dumps({"阶段": "公开外壳轻量静态检查", "通过": True, "检查文件数": len(paths),
                      "归档纯内存拒绝场景数": cases, "研究交付纯内存拒绝场景数": research_cases,
                      "加密配置拒绝场景数": encryption_cases, "研究公钥已配置": configured, "合成统计拒绝场景数": synthetic_cases,
                      "CI阶段纯内存场景数": failure_cases, "失败诊断纯内存场景数": diagnostic_cases,
                      "读取私有源码": False, "执行编译": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("公开外壳静态检查失败；不打印私有信息，不执行构建。", file=sys.stderr)
        raise SystemExit(2)
