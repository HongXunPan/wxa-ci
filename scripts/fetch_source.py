"""仅在获准 CI 中按完整提交获取固定私有仓，不打印网络响应或 Git 信息。"""
import io
import json
import os
import shutil
import tarfile
import urllib.error
import urllib.request
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from ci_contract import ROOT, SOURCE_REPOSITORY, context, require

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def read_limited(response, limit):
    data = response.read(limit + 1)
    require(len(data) <= limit, "响应超限")
    return data


def api(path, token, limit):
    request = urllib.request.Request("https://api.github.com/repos/" + SOURCE_REPOSITORY + path,
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2026-03-10"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=25) as response:
            return read_limited(response, limit)
    except urllib.error.HTTPError as error:
        if error.code != 302 or not path.startswith("/tarball/"):
            raise ValueError("源码服务请求失败") from None
        location = error.headers.get("Location", "")
        target = urlsplit(location)
        require(target.scheme == "https" and target.hostname == "codeload.github.com" and
                target.port in (None, 443) and not target.username and not target.password,
                "源码下载重定向不符")
        # 下载凭据只在 API 请求头内；不将其转发到重定向主机。
        with urllib.request.build_opener(NoRedirect).open(location, timeout=25) as response:
            return read_limited(response, limit)


def source_members(archive):
    members, prefix, total, seen = [], None, 0, set()
    for member in archive:
        require(len(members) < 5000, "源码成员数超限")
        path = PurePosixPath(member.name)
        require(not path.is_absolute() and path.parts and ".." not in path.parts and
                ".git" not in path.parts and (member.isdir() or member.isreg()), "源码成员不安全")
        prefix = prefix or path.parts[0]
        require(path.parts[0] == prefix, "源码根目录不唯一")
        relative = PurePosixPath(*path.parts[1:])
        require(str(relative) not in seen and (relative.parts or member.isdir()), "源码成员重复或位置不符")
        seen.add(str(relative))
        total += member.size
        require(0 <= member.size <= 8 * 1024 * 1024 and total <= MAX_EXPANDED, "源码展开超限")
        members.append((relative, member))
    require(bool(members), "源码归档为空")
    return members


def extract_source(data, destination):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for relative, member in source_members(archive):
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                require(relative.parts, "源码文件位置不符")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)


def main():
    os.umask(0o077)
    sha, _ = context()
    token = os.environ.pop("WXA_SOURCE_READ_TOKEN", "")
    require(bool(token), "缺少只读源码凭证")
    comparison = json.loads(api("/compare/" + sha + "...main", token, 4 * 1024 * 1024))
    require(comparison["status"] in ("ahead", "identical") and
            comparison["base_commit"]["sha"] == sha and comparison["merge_base_commit"]["sha"] == sha,
            "指定提交不属于已合并主线")
    data = api("/tarball/" + sha, token, MAX_ARCHIVE)
    del token
    temporary = ROOT / ".codex-tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    require(temporary.is_dir() and not temporary.is_symlink(), "受管根目录不符")
    destination = temporary / "source"
    destination.mkdir(mode=0o700)
    extract_source(data, destination)
    print("源码获取完成。")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("源码获取失败；未打印响应、提交说明或私有路径。") from None
