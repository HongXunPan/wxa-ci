"""公开执行外壳的固定身份和交付白名单，不接受任意项目或命令。"""
import hashlib
import os
import re
import tarfile
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_REPOSITORY = "HongXunPan/wxa-ci"
SOURCE_REPOSITORY = "HongXunPan/wechat-assistant"
WORKFLOW = ".github/workflows/macos.yml"
FILES = (
    "WeChatAssistant-demo-macos-x86_64.zip",
    "WCDBSyntheticProbe-macos-x86_64.tgz",
    "LiveFilesGuardProbe-macos-x86_64.tgz",
)
RESEARCH_ROLES = {
    "research": {"archive": "WeChatAssistantResearch-macos-x86_64.tgz", "name": "WeChatAssistantResearch",
                 "identifier": "io.github.hongxunpan.wechat-assistant.research-sample",
                 "disable_library_validation": False},
    "reader": {"archive": "SourceReaderCandidate-macos-x86_64.tgz", "name": "SourceReaderCandidate",
               "identifier": "io.github.hongxunpan.wechat-assistant.source-reader.candidate",
               "disable_library_validation": True},
}
MAX_FILE = 128 * 1024 * 1024
RESEARCH_CIPHER = "research-bundle.zip.age"
RESEARCH_ENVELOPE = "envelope.json"
MAX_RESEARCH_PLAIN = 2 * MAX_FILE + 64 * 1024
MAX_RESEARCH_CIPHER = 2 * MAX_FILE + 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def delivery_kind():
    kind = os.environ.get("WXA_DELIVERY_KIND", "offline")
    require(kind in ("offline", "research"), "交付档位不符")
    return kind


def delivery_files(kind):
    require(type(kind) is str and kind in ("offline", "research"), "交付档位不符")
    return FILES if kind == "offline" else tuple(item["archive"] for item in RESEARCH_ROLES.values())


def upload_files(kind):
    require(kind in ("offline", "research"), "上传档位不符")
    return (*FILES, "manifest.json") if kind == "offline" else (RESEARCH_CIPHER, RESEARCH_ENVELOPE)


def recipient_fingerprint(recipient):
    require(type(recipient) is str and re.fullmatch(r"age1[ac-hj-np-z02-9]{58}", recipient), "研究公钥格式不符")
    return hashlib.sha256((recipient + "\n").encode("ascii")).hexdigest()


def hex_digest(value, length):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "身份清单字段重复")
        result[key] = value
    return result


def validate_research_identity(value):
    require(type(value) is dict and set(value) == {"schema", "roles", "bindings"} and
            type(value["schema"]) is int and value["schema"] == 1, "研究身份格式不符")
    roles = value["roles"]
    require(type(roles) is dict and set(roles) == set(RESEARCH_ROLES), "研究角色不符")
    fields = {"name", "identifier", "architecture", "size", "sha256", "cdhash", "hardened_runtime",
              "disable_library_validation"}
    for key, expected in RESEARCH_ROLES.items():
        role = roles[key]
        require(type(role) is dict and set(role) == fields and
                all(role[name] == expected[name] for name in ("name", "identifier")) and
                role["architecture"] == "x86_64" and type(role["size"]) is int and 0 < role["size"] <= MAX_FILE and
                hex_digest(role["sha256"], 64) and hex_digest(role["cdhash"], 40) and
                role["hardened_runtime"] is True and
                role["disable_library_validation"] is expected["disable_library_validation"], "研究角色身份不符")
    bindings = value["bindings"]
    require(type(bindings) is dict and set(bindings) == {"app_cdhash", "research_cdhash"} and
            hex_digest(bindings["app_cdhash"], 40) and bindings["research_cdhash"] == roles["research"]["cdhash"],
            "读取器配套绑定不符")
    return value


def inspect_research_archive(archive, role):
    member = archive.next()
    require(member is not None and member.isfile() and member.name == role["name"] and
            member.size == role["size"] and 0 < member.size <= MAX_FILE, "研究归档成员不符")
    value, count = hashlib.sha256(), 0
    with archive.extractfile(member) as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
            count += len(block)
            require(count <= member.size, "研究成员超限")
    require(count == member.size and value.hexdigest() == role["sha256"] and archive.next() is None,
            "研究归档摘要、数量或大小不符")


def research_fields(build):
    path = build / "research-identity.json"
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 8192, "研究身份文件不符")
    identity = validate_research_identity(json.loads(path.read_text(), object_pairs_hook=unique_object))
    for key, expected in RESEARCH_ROLES.items():
        with tarfile.open(build / expected["archive"], "r:gz") as archive:
            inspect_research_archive(archive, identity["roles"][key])
    return {"schema": 2, "delivery": "research", "roles": identity["roles"], "bindings": identity["bindings"]}


def validate_research_manifest(value, source_sha, ci):
    require(type(value) is dict and set(value) == {"schema", "delivery", "source", "ci", "build", "files", "roles", "bindings"} and
            type(value["schema"]) is int and value["schema"] == 2 and value["delivery"] == "research",
            "研究内层清单格式不符")
    require(value["source"] == {"repository": SOURCE_REPOSITORY, "sha": source_sha, "ref": "refs/heads/main"} and
            type(value["ci"]) is dict and type(value["ci"].get("run_id")) is int and
            type(value["ci"].get("run_attempt")) is int and value["ci"] == ci, "研究内层构建身份不符")
    validate_research_identity({"schema": 1, "roles": value["roles"], "bindings": value["bindings"]})
    build = value["build"]
    require(type(build) is dict and set(build) == {"architecture", "deployment", "xcode", "tests"} and
            build["architecture"] == "x86_64" and build["deployment"] == "13.0" and build["tests"] == "passed" and
            type(build["xcode"]) is str and re.fullmatch(r"Xcode 16\.4\nBuild version [A-Za-z0-9]+", build["xcode"]),
            "研究内层工具链或测试结论不符")
    files = value["files"]
    require(type(files) is list and len(files) == 2 and all(type(item) is dict and
            set(item) == {"name", "size", "sha256"} and item["name"] in delivery_files("research") and
            type(item["size"]) is int and 0 < item["size"] <= MAX_FILE and hex_digest(item["sha256"], 64)
            for item in files) and {item["name"] for item in files} == set(delivery_files("research")),
            "研究内层交付描述不符")
    return value


def context():
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_OS") == "macOS" and
            os.environ.get("RUNNER_ARCH") == "X64" and os.geteuid() != 0,
            "仅允许普通用户 Intel macOS Actions 作业")
    require(os.environ.get("GITHUB_REPOSITORY") == CI_REPOSITORY and
            os.environ.get("GITHUB_REF") == "refs/heads/main" and
            os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
            os.environ.get("GITHUB_WORKFLOW_REF") == CI_REPOSITORY + "/" + WORKFLOW + "@refs/heads/main",
            "公开执行身份不符")
    source = os.environ.get("WXA_SOURCE_SHA", "")
    workflow_sha = os.environ.get("GITHUB_SHA", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch("[0-9a-f]{40}", source) and re.fullmatch("[0-9a-f]{40}", workflow_sha) and
            re.fullmatch("[1-9][0-9]*", run) and re.fullmatch("[1-9][0-9]*", attempt), "提交或运行标识不符")
    return source, {"repository": CI_REPOSITORY, "sha": workflow_sha,
                    "run_id": int(run), "run_attempt": int(attempt), "workflow": WORKFLOW}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()
