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

# 仅允许既有编排中的固定编号；含义由私有说明维护，不公开路径或命令。
NATIVE_STAGES = frozenset((*range(100, 106), *range(110, 124), *range(130, 138),
                         *range(200, 215), *range(230, 239), 300, *range(301, 329), *range(340, 346)))


def parse_native_stage(value):
    """只解析有界私有报告中的固定标记，不返回任何原始行。"""
    if type(value) is not bytes or len(value) > 16 * 1024 or not value.endswith(b"\n"):
        return 3
    stage = 3
    for line in value.split(b"\n"):
        if line.startswith(b"WXA_CI_STAGE"):
            matched = re.fullmatch(rb"WXA_CI_STAGE_V1 ([0-9]{3})", line)
            if not matched or int(matched[1]) not in NATIVE_STAGES:
                return 3
            stage = int(matched[1])
    return stage


def native_stage(report):
    try:
        if report.is_symlink():
            return 3
        with report.open("rb") as source:
            return parse_native_stage(source.read(16 * 1024 + 1))
    except OSError:
        return 3


class BuildProgress:
    def __init__(self):
        self.stage, self.exit_code = 1, 0

    def enter(self, stage):
        self.stage, self.exit_code = stage, 0

    def run(self, stage, arguments, *, report=None, **options):
        self.enter(stage)
        result = subprocess.run(arguments, **options)
        if result.returncode:
            self.exit_code = result.returncode
            if stage == 3 and report is not None:
                self.stage = native_stage(report)
        require(result.returncode == 0, "CI 子步骤未完成")
        return result

    def failure_frame(self):
        stage = self.stage if type(self.stage) is int and self.stage in NATIVE_STAGES | set(range(1, 12)) else 0
        code = self.exit_code if type(self.exit_code) is int and -127 <= self.exit_code <= 255 else 0
        return f"WXA_CI_FAILURE_V1 {stage:03d} {code}"


def copy_delivery(build, payload, kind):
    files = []
    for name in delivery_files(kind):
        path = build / name
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_FILE,
                "交付文件不符或超限")
        target = payload / name
        shutil.copyfile(path, target)
        files.append({"name": name, "size": target.stat().st_size, "sha256": digest(target)})
    return files


def main(progress):
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
    commands = ((2, ["/usr/bin/python3", "scripts/check_static.py"]), (3, ["/bin/bash", "scripts/ci-build.sh"]))
    with (private / "build.log").open("xb") as log:
        for stage, command in commands:
            progress.run(stage, command, report=report, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                         stdout=log, stderr=subprocess.STDOUT)
    progress.enter(4)
    statistics = collect_report(private / "build.log", (source / "Tests/CopyLocalTests.c").is_file())
    version = progress.run(5, ["/usr/bin/xcodebuild", "-version"], env=environment, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=15)
    require(version.returncode == 0 and re.fullmatch(r"Xcode 16\.4\nBuild version [A-Za-z0-9]+\n?", version.stdout),
            "工具链版本不符")
    progress.enter(6)
    delivery = ROOT / ".codex-tmp/delivery"
    delivery.mkdir(mode=0o700)
    payload = delivery
    if kind == "research":
        payload = private / "research-payload"
        payload.mkdir(mode=0o700)
    files = copy_delivery(build, payload, kind)
    progress.enter(7)
    manifest = {"schema": 1, "source": {"repository": SOURCE_REPOSITORY, "sha": source_sha, "ref": "refs/heads/main"},
                "ci": ci, "build": {"architecture": "x86_64", "deployment": "13.0",
                "xcode": version.stdout.strip(), "tests": "passed"}, "files": files}
    if kind == "research":
        manifest.update(research_fields(build))
    with (payload / "manifest.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, ensure_ascii=False, indent=2)
        output.write("\n")
    progress.enter(8)
    if kind == "research":
        tools = prepare_tools(private / "age-tools")
        # 只在研究 CI 中运行一次性合成密钥用例，不获取父仓或真实解密材料。
        with (private / "research-tests.log").open("xb") as log:
            checked = progress.run(9, ["/usr/bin/python3", "Tests/ResearchDeliveryEncryptionTests.py",
                "--age-tool-directory", str(tools)], cwd=source, env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            require(checked.returncode == 0, "研究加密合成测试未通过")
        progress.enter(10)
        seal_research(payload, delivery, tools, recipient)
    progress.enter(11)
    publish_report(statistics)
    print("编译及合成测试通过；白名单交付已生成，未公开源码级诊断。")


if __name__ == "__main__":
    progress = BuildProgress()
    try:
        main(progress)
    except Exception:
        print(progress.failure_frame(), flush=True)
        raise SystemExit("构建或交付未完成；不上传原始日志，不自动重跑。") from None
