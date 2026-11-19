"""显式研究失败的单日志加密通道；不改变原失败结论。"""
import json
import os
import stat
import subprocess

from ci_contract import ROOT, SOURCE_REPOSITORY, context, digest, recipient_fingerprint, require
from research_encryption import prepare_tools, tool_environment, validate_tools

PURPOSE = "xctest-failure-v1"
CIPHER = "xctest.log.age"
ENVELOPE = "diagnostic-envelope.json"
MAX_PLAIN = 8 * 1024 * 1024
MAX_CIPHER = MAX_PLAIN + 64 * 1024
STAGES = {130: (PURPOSE, CIPHER, "xctest"),
          9: ("research-crypto-failure-v1", "research-tests.json.age", "research_crypto")}


def stage_spec(stage):
    require(type(stage) is int and stage in STAGES, "失败诊断阶段不符")
    return STAGES[stage]


def encode_log(data, stage):
    stage_spec(stage)
    require(type(data) is bytes and 0 < len(data) <= MAX_PLAIN, "失败诊断日志大小不符")
    if stage == 130:
        return data
    # 来源头只进入密文，用于区分两个固定仓库；不接受外部路径输入。
    roots = {"ci": str(ROOT), "source": str(ROOT / ".codex-tmp/source")}
    require(len(json.dumps(roots).encode("utf-8")) <= 4096, "失败诊断来源头超限")
    encoded = (json.dumps({"schema": 1, "roots": roots, "log": data.decode("utf-8")},
                          ensure_ascii=True) + "\n").encode("utf-8")
    require(len(encoded) <= MAX_PLAIN, "失败诊断编码后超限")
    return encoded


def diagnostic_requested(kind):
    value = os.environ.get("WXA_FAILURE_DIAGNOSTIC", "false")
    require(value in ("false", "true"), "失败诊断开关无效")
    require(value == "false" or kind == "research", "失败诊断仅允许显式研究档位")
    return value == "true"


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700, "失败诊断目录不符")


def read_test_log(source, private=None, stage=130):
    stage_spec(stage)
    require(source == ROOT / ".codex-tmp/source" and not source.is_symlink() and
            not (source / "build").is_symlink(), "失败诊断源目录不符")
    path = source / "build/test.log" if stage == 130 else private / "research-tests.log"
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
                stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= MAX_PLAIN,
                "失败诊断日志类型或大小不符")
        data = stream.read(MAX_PLAIN + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, name) == getattr(after, name) for name in fields) and
                len(data) == before.st_size, "失败诊断日志读取期间发生变化")
    return data


def seal_log(data, delivery, tools, recipient, exit_code, stage=130):
    source_sha, ci = context()
    purpose, cipher_name, unused_kind = stage_spec(stage)
    require(type(data) is bytes and 0 < len(data) <= MAX_PLAIN and
            type(exit_code) is int and -127 <= exit_code <= 255 and exit_code != 0,
            "失败诊断输入不符")
    data = encode_log(data, stage)
    fingerprint = recipient_fingerprint(recipient)
    validate_tools(tools)
    private_directory(delivery)
    require(not any(delivery.iterdir()), "失败诊断交付目录必须为空")
    created, complete = [], False
    try:
        cipher = delivery / cipher_name
        descriptor = os.open(str(cipher), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created.append(cipher)
        with os.fdopen(descriptor, "wb") as output:
            result = subprocess.run([str(tools / "age"), "-e", "-r", recipient], input=data,
                stdout=output, stderr=subprocess.PIPE, env=tool_environment(tools), timeout=60)
            require(result.returncode == 0 and len(result.stderr) <= 64 * 1024, "失败诊断加密未完成")
            output.flush()
            os.fsync(output.fileno())
        info = cipher.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_CIPHER,
                "失败诊断密文超限")
        envelope = {"schema": 1, "purpose": purpose, "format": "age-v1",
            "source": {"repository": SOURCE_REPOSITORY, "sha": source_sha, "ref": "refs/heads/main"},
            "ci": ci, "failure": {"stage": stage, "exit_code": exit_code}, "recipient_sha256": fingerprint,
            "cipher": {"name": cipher_name, "size": info.st_size, "sha256": digest(cipher)}}
        encoded = (json.dumps(envelope, indent=2) + "\n").encode("utf-8")
        require(len(encoded) <= 16 * 1024, "失败诊断封套超限")
        path = delivery / ENVELOPE
        with path.open("xb") as output:
            created.append(path)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        complete = True
        return envelope
    finally:
        if not complete:
            for path in created:
                path.unlink()


def publish_failure(source, private, recipient, exit_code, stage=130):
    unused, ci = context()
    unused_purpose, unused_cipher, kind = stage_spec(stage)
    require(private == ROOT / ".codex-tmp" / ("ci-" + str(ci["run_id"]) + "-" + str(ci["run_attempt"])),
            "失败诊断运行目录不符")
    private_directory(private)
    data = read_test_log(source, private, stage)
    # 阶段9只复用阶段8已核验工具，不下载第二套，也不改变原失败。
    tools = prepare_tools(private / "failure-age-tools") if stage == 130 else private / "age-tools"
    delivery = ROOT / ".codex-tmp/failure-diagnostic"
    delivery.mkdir(mode=0o700)
    seal_log(data, delivery, tools, recipient, exit_code, stage)
    descriptor = os.open(os.environ["GITHUB_OUTPUT"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "wb") as output:
        info = os.fstat(output.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1,
                "失败诊断步骤输出不符")
        output.write(("diagnostic_kind=" + kind + "\ndiagnostic_ready=true\n").encode("ascii"))
        output.flush()
        os.fsync(output.fileno())


def collect_failure(progress, enabled, source, private, recipient):
    """诊断异常不能替换原始构建阶段、退出码或失败状态。"""
    if not enabled or progress.stage not in STAGES or progress.exit_code == 0:
        return False
    try:
        publish_failure(source, private, recipient, progress.exit_code, progress.stage)
        return True
    except Exception:
        # 不输出原始异常，不回退明文，不重试或修改构建进度。
        return False
