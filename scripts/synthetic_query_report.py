"""仅把完整、固定字段的纯合成成本帧重新编码到公开控制台。"""
import json

PREFIX = b"WXA_SYNTHETIC_QUERY_V1 "
MAX_LOG = 64 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_FRAME = 2048
BEGIN = {"kind": "begin", "schema": 1, "experiment": "copy_local_v1", "cases": 160, "variants": 3, "records": 480}
END = {"kind": "end", "records": 480, "semantic_cases": 51, "boundary_cases": 16, "builder_cases": 20}
COUNTERS = {"scan", "sort", "vm"}
TIMES = {"prepare_us", "bind_us", "step_us", "finalize_us", "phase_us", "total_us"}
COST_KEYS = {"kind", "case", "strategy", "status", "statements"} | COUNTERS | TIMES


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "合成统计字段重复")
        result[key] = value
    return result


def fixed(value, expected):
    require(type(value) is dict and set(value) == set(expected), "合成统计起止字段不符")
    require(all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()),
            "合成统计起止值不符")


def cost(value):
    require(type(value) is dict and set(value) == COST_KEYS and value["kind"] == "cost", "合成成本字段不符")
    limits = {"case": 159, "strategy": 2, "status": 3, "statements": 256,
              **{key: 999999999999 for key in COUNTERS}, **{key: 60000000 for key in TIMES}}
    require(all(type(value[key]) is int and 0 <= value[key] <= limit for key, limit in limits.items()),
            "合成成本仅接受限定整数")
    require(value["status"] in (0, 3) and value["total_us"] >= value["phase_us"], "合成成本状态或耗时不符")
    require(value["statements"] != 0 or all(value[key] == 0 for key in COUNTERS), "无语句时不能有执行计数")
    return {key: value[key] for key in sorted(COST_KEYS)}


def frames(stream):
    total = 0
    while True:
        line = stream.readline(MAX_LINE + 1)
        if not line:
            return
        total += len(line)
        require(total <= MAX_LOG, "私有构建输出超过统计扫描上限")
        marked = line.startswith(PREFIX)
        if len(line) > MAX_LINE and not line.endswith(b"\n"):
            require(not marked, "合成统计帧超限")
            # 丢弃超长非统计行，不保留、拼接或回传原始内容。
            while line and not line.endswith(b"\n"):
                line = stream.readline(MAX_LINE + 1)
                total += len(line)
                require(total <= MAX_LOG, "私有构建输出超过统计扫描上限")
            continue
        if marked:
            require(line.endswith(b"\n") and len(line) <= MAX_FRAME, "合成统计帧截断或超限")
            yield json.loads(line[len(PREFIX):].decode("ascii"), object_pairs_hook=unique)


def validate_report(values, required):
    require(type(required) is bool, "必须显式指定本次源码是否包含实验")
    started, ended, records = False, False, {}
    for value in values:
        require(required and not ended, "未启用实验或结束后仍有统计帧")
        if not started:
            fixed(value, BEGIN)
            started = True
        elif type(value) is dict and value.get("kind") == "end":
            fixed(value, END)
            require(len(records) == 480, "合成成本记录未收全")
            ended = True
        else:
            row = cost(value)
            key = (row["case"], row["strategy"])
            require(key not in records and len(records) < 480, "合成成本重复或超量")
            records[key] = row
    if not required:
        require(not started, "旧源码不能自报新实验")
        return []
    require(started and ended and set(records) == {(case, strategy) for case in range(160) for strategy in range(3)},
            "合成统计起止或组合不完整")
    return [dict(BEGIN), *(records[key] for key in sorted(records)), dict(END)]


def parse_report(stream, required):
    return validate_report(frames(stream), required)


def collect_report(path, required):
    with path.open("rb") as stream:
        return parse_report(stream, required)


def publish_report(report):
    require(type(report) is list, "合成统计发布对象不符")
    if not report:
        return
    # 发布边界再次完整验证，调用方不能传半份对象绕过过滤。
    for value in validate_report(report, True):
        print(PREFIX.decode("ascii") + json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
