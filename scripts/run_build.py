"""将构建和内部摘要留在作业内，只整理固定白名单产物。"""
import json
import os
import re
import shutil
import subprocess

from ci_contract import (MAX_FILE, ROOT, SOURCE_REPOSITORY, context, delivery_files, delivery_kind,
                         digest, require, research_fields)
from research_encryption import configured_recipient, prepare_tools, seal_research
from synthetic_query_report import collect_report, publish_report


def main():
    os.umask(0o077)
    source_sha, ci = context()
    kind = delivery_kind()
    require(not os.environ.get("WXA_SOURCE_READ_TOKEN"), "构建步骤不得接收源码凭证")
    recipient = configured_recipient() if kind == "research" else None
    source = ROOT / ".codex-tmp/source"
    require(source.is_dir() and not source.is_symlink(), "源码目录不符")
    private = ROOT / ".codex-tmp" / ("ci-" + str(ci["run_id"]) + "-" + str(ci["run_attempt"]))
    private.mkdir(mode=0o700, parents=True)
    build = source / "build"
    build.mkdir(mode=0o700)
    report = build / "ci-private-summary.md"
    report.touch(mode=0o600)
    environment = dict(os.environ, WXA_SOURCE_REPOSITORY=SOURCE_REPOSITORY,
                       WXA_SOURCE_REF="refs/heads/main", WXA_PRIVATE_REPORT=str(report), WXA_DELIVERY_KIND=kind)
    # 不改写 GitHub 内置身份变量；所有私有命令输出进入内部文件。
    commands = (["/usr/bin/python3", "scripts/check_static.py"], ["/bin/bash", "scripts/ci-build.sh"])
    with (private / "build.log").open("xb") as log:
        for command in commands:
            result = subprocess.run(command, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT)
            require(result.returncode == 0, "编译或合成测试失败")
    statistics = collect_report(private / "build.log", (source / "Tests/CopyLocalTests.c").is_file())
    version = subprocess.run(["/usr/bin/xcodebuild", "-version"], env=environment, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=15)
    require(version.returncode == 0 and re.fullmatch(r"Xcode 16\.4\nBuild version [A-Za-z0-9]+\n?", version.stdout),
            "工具链版本不符")
    delivery = ROOT / ".codex-tmp/delivery"
    delivery.mkdir(mode=0o700)
    payload = delivery
    if kind == "research":
        payload = private / "research-payload"
        payload.mkdir(mode=0o700)
    files = []
    for name in delivery_files(kind):
        path = build / name
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_FILE,
                "交付文件不符或超限")
        target = payload / name
        shutil.copyfile(path, target)
        files.append({"name": name, "size": target.stat().st_size, "sha256": digest(target)})
    manifest = {"schema": 1, "source": {"repository": SOURCE_REPOSITORY, "sha": source_sha, "ref": "refs/heads/main"},
                "ci": ci, "build": {"architecture": "x86_64", "deployment": "13.0",
                "xcode": version.stdout.strip(), "tests": "passed"}, "files": files}
    if kind == "research":
        manifest.update(research_fields(build))
    with (payload / "manifest.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, ensure_ascii=False, indent=2)
        output.write("\n")
    if kind == "research":
        tools = prepare_tools(private / "age-tools")
        # 只在研究 CI 中运行一次性合成密钥用例，不获取父仓或真实解密材料。
        with (private / "research-tests.log").open("xb") as log:
            checked = subprocess.run(["/usr/bin/python3", "Tests/ResearchDeliveryEncryptionTests.py",
                "--age-tool-directory", str(tools)], cwd=source, env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            require(checked.returncode == 0, "研究加密合成测试未通过")
        seal_research(payload, delivery, tools, recipient)
    publish_report(statistics)
    print("编译及合成测试通过；白名单交付已生成，未公开源码级诊断。")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("构建或交付未完成；不上传原始日志，不自动重跑。") from None
