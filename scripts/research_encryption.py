"""研究交付的固定工具、公钥及加密封套；不接收任何真实解密材料。"""
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import time
import urllib.request
import zipfile

from ci_contract import (MAX_FILE, MAX_RESEARCH_CIPHER, MAX_RESEARCH_PLAIN, RESEARCH_CIPHER,
                         RESEARCH_ENVELOPE, RESEARCH_ROLES, ROOT, context, delivery_files, digest,
                         inspect_research_payload, recipient_fingerprint, require, unique_object,
                         validate_research_manifest)

VERSION = "v1.3.2"
ASSET_URL = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-amd64.tar.gz"
ASSET_SIZE = 19376787
ASSET_SHA256 = "1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539"
TOOL_HASHES = {
    "age": "0c2fbcffab91d0af398162a8ed792e096916c8c47c3c400e303904431103f492",
    "age-keygen": "33c25cc60fdfbb27438f885e0e9f6e2e2c29c0a64449738bff57b6aebe42f67f",
    "age-plugin-batchpass": "2eac7c4e16ec2b096a0cd80ec61f8aa995bd0571b59184ca89fab9fc5532e296",
}


def parse_recipient_config(value):
    require(type(value) is dict and set(value) == {"schema", "recipient"} and
            type(value["schema"]) is int and value["schema"] == 1, "研究公钥配置格式不符")
    if value["recipient"] is not None:
        recipient_fingerprint(value["recipient"])
    return value["recipient"]


def configured_recipient():
    path = ROOT / "config/research-recipient.json"
    regular(path, 4096)
    value = parse_recipient_config(json.loads(path.read_text(), object_pairs_hook=unique_object))
    require(value is not None, "研究公钥尚未配置；停止研究发布，不回退明文")
    return value


def regular(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
            "研究交付文件类型或大小不符")
    return info


def tool_environment(tools):
    return {"PATH": str(tools) + ":/usr/bin:/bin", "HOME": str(tools.parent),
            "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}


def validate_tools(tools):
    info = tools.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700, "研究工具目录不符")
    for name, expected in TOOL_HASHES.items():
        path = tools / name
        state = regular(path, 32 * 1024 * 1024)
        require(state.st_uid == os.geteuid() and stat.S_IMODE(state.st_mode) == 0o500 and
                digest(path) == expected, "固定研究工具摘要或权限不符")


def prepare_tools(directory):
    context()
    require(directory.is_absolute() and directory.is_relative_to(ROOT / ".codex-tmp") and
            not directory.exists() and not directory.is_symlink(), "研究工具必须使用新的受管目录")
    deadline, data = time.monotonic() + 90, bytearray()
    # 固定公开下载地址，不查询匿名 API，不使用构建或源码凭证，也不重试。
    with urllib.request.urlopen(ASSET_URL, timeout=25) as source:
        require(source.status == 200 and source.geturl().startswith("https://"), "官方工具下载响应不符")
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            data.extend(block)
            require(len(data) <= ASSET_SIZE and time.monotonic() < deadline, "官方工具下载超限或超时")
    require(len(data) == ASSET_SIZE and hashlib.sha256(data).hexdigest() == ASSET_SHA256,
            "官方工具归档长度或摘要不符")
    selected, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for item in archive:
            require(item.name not in seen and len(seen) < 32 and not item.name.startswith("/") and
                    ".." not in item.name.split("/") and (item.isdir() or item.isfile()), "官方工具归档成员不符")
            seen.add(item.name)
            if item.isfile():
                total += item.size
                require(0 < item.size <= 32 * 1024 * 1024 and total <= 128 * 1024 * 1024, "工具归档超限")
            for name in TOOL_HASHES:
                if item.name == "age/" + name:
                    require(item.isfile(), "固定工具不是普通文件")
                    selected[name] = archive.extractfile(item).read(item.size + 1)
                    require(len(selected[name]) == item.size and
                            hashlib.sha256(selected[name]).hexdigest() == TOOL_HASHES[name], "固定工具字节不符")
    require(set(selected) == set(TOOL_HASHES), "官方归档缺少固定工具，不自行补装或编译")
    directory.mkdir(mode=0o700)
    for name, content in selected.items():
        path = directory / name
        with path.open("xb") as output:
            output.write(content)
        path.chmod(0o500)
    validate_tools(directory)
    for name in TOOL_HASHES:
        process = subprocess.run([str(directory / name), "--version"], env=tool_environment(directory),
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        require(process.returncode == 0 and process.stdout.strip() == VERSION.encode("ascii"), "固定工具版本执行失败")
    return directory


def seal_research(payload, delivery, tools, recipient):
    source_sha, ci = context()
    fingerprint = recipient_fingerprint(recipient)
    validate_tools(tools)
    require(set(path.name for path in payload.iterdir()) == set(delivery_files("research")) | {"manifest.json"},
            "研究内层存在额外或缺失文件")
    regular(payload / "manifest.json", 16 * 1024)
    manifest = json.loads((payload / "manifest.json").read_text(), object_pairs_hook=unique_object)
    validate_research_manifest(manifest, source_sha, ci)
    for item in manifest["files"]:
        state = regular(payload / item["name"], MAX_FILE)
        require(state.st_size == item["size"] and digest(payload / item["name"]) == item["sha256"], "研究内层文件字节不符")
    for role, expected in RESEARCH_ROLES.items():
        inspect_research_payload(payload / expected["archive"], role, manifest["roles"][role])
    state = delivery.lstat()
    require(stat.S_ISDIR(state.st_mode) and state.st_uid == os.geteuid() and
            stat.S_IMODE(state.st_mode) == 0o700 and not any(delivery.iterdir()), "研究交付目录必须私有且为空")
    inner = payload / ".research-payload.zip"
    created, complete = [], False
    try:
        with zipfile.ZipFile(inner, "x", compression=zipfile.ZIP_STORED) as archive:
            for name in (*delivery_files("research"), "manifest.json"):
                archive.write(payload / name, name)
        regular(inner, MAX_RESEARCH_PLAIN)
        cipher = delivery / RESEARCH_CIPHER
        with cipher.open("xb") as output:
            created.append(cipher)
            process = subprocess.run([str(tools / "age"), "-e", "-r", recipient, str(inner)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.PIPE,
                env=tool_environment(tools), timeout=60)
            require(process.returncode == 0 and len(process.stderr) <= 64 * 1024, "研究交付加密未完成")
            output.flush()
            os.fsync(output.fileno())
        info = regular(cipher, MAX_RESEARCH_CIPHER)
        envelope = {"schema": 1, "delivery": "research", "format": "age-v1", "source": manifest["source"],
                    "ci": manifest["ci"], "recipient_sha256": fingerprint,
                    "cipher": {"name": RESEARCH_CIPHER, "size": info.st_size, "sha256": digest(cipher)}}
        encoded = (json.dumps(envelope, indent=2) + "\n").encode("utf-8")
        require(len(encoded) <= 16 * 1024, "研究封套超限")
        path = delivery / RESEARCH_ENVELOPE
        with path.open("xb") as output:
            created.append(path)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        complete = True
        return envelope
    finally:
        if inner.is_file() and not inner.is_symlink():
            inner.unlink()
        if not complete:
            for path in created:
                path.unlink()
