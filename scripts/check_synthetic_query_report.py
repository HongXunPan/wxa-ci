"""固定统计出口的纯内存正负断言；不读构建日志、不执行实验。"""
import copy
import io
import json
from unittest.mock import patch

from synthetic_query_report import BEGIN, END, PREFIX, MAX_FRAME, MAX_LINE, parse_report, publish_report


def fixture():
    rows = [dict(BEGIN)]
    for case in range(160):
        for strategy in range(3):
            rows.append({"kind": "cost", "case": case, "strategy": strategy, "status": 0, "statements": 1,
                         "scan": 0, "sort": 0, "vm": 10, "prepare_us": 1, "bind_us": 1,
                         "step_us": 1, "finalize_us": 1, "phase_us": 4, "total_us": 5})
    return rows + [dict(END)]


def encoded(rows):
    return b"".join(PREFIX + json.dumps(row).encode("ascii") + b"\n" for row in rows)


def check_wiring(root):
    build = (root / "scripts/run_build.py").read_text()
    collection = 'collect_report(private / "build.log", (source / "Tests/CopyLocalTests.c").is_file())'
    assert build.count("collect_report(") == 1 and collection in build and build.count("publish_report(statistics)") == 1
    assert build.index('require(result.returncode == 0') < build.index(collection) < build.index('manifest = ')
    assert build.index('seal_research(payload, delivery, tools, recipient)') < build.index('publish_report(statistics)')
    module = (root / "scripts/synthetic_query_report.py").read_text()
    assert 'for value in validate_report(report, True)' in module and 'stream.readline(MAX_LINE + 1)' in module
    assert 'value[key]' in module and 'type(value[key]) is int' in module


def check_synthetic_query_report(root):
    check_wiring(root)
    original = fixture()
    valid = parse_report(io.BytesIO(b"private synthetic diagnostic\n" + encoded(original)), True)
    assert len(valid) == 482 and valid[1]["case"] == 0 and valid[-2]["case"] == 159
    assert parse_report(io.BytesIO(b"private synthetic diagnostic\n"), False) == []
    assert len(parse_report(io.BytesIO(b"x" * (MAX_LINE + 9) + b"\n" + encoded(original)), True)) == 482
    timeout = copy.deepcopy(original)
    timeout[1]["status"] = 3
    assert parse_report(io.BytesIO(encoded(timeout)), True)[1]["status"] == 3
    mutations = [lambda rows: rows.pop(), lambda rows: rows.pop(1), lambda rows: rows.insert(1, dict(rows[1])),
        lambda rows: rows.append(dict(END)), lambda rows: rows[0].update(schema=True),
        lambda rows: rows[-1].update(semantic_cases=50), lambda rows: rows[1].update(case=160),
        lambda rows: rows[1].update(strategy=3), lambda rows: rows[1].update(status=6),
        lambda rows: rows[1].update(statements=True), lambda rows: rows[1].update(vm=-1),
        lambda rows: rows[1].update(scan=1000000000000), lambda rows: rows[1].update(step_us=60000001),
        lambda rows: rows[1].update(total_us=0), lambda rows: rows[1].update(statements=0),
        lambda rows: rows[1].update(sql="synthetic forbidden query"),
        lambda rows: rows[1].update(vm="synthetic forbidden value")]
    cases = []
    for change in mutations:
        rows = copy.deepcopy(original)
        change(rows)
        cases.append((encoded(rows), True))
    # 无语句时非零执行计数须独立拒绝。
    rows = copy.deepcopy(original)
    rows[1].update(statements=0, vm=1)
    cases.extend([(encoded(rows), True), (encoded(original), False), (b"", True),
        (encoded(original)[:-1], True), (PREFIX + b"x" * MAX_FRAME + b"\n", True),
        (PREFIX + b'{"kind":"begin","kind":"begin"}\n', True)])
    # 上一条仅清零语句数时也有非零 vm，故同样应拒绝。
    for content, required in cases:
        try:
            parse_report(io.BytesIO(content), required)
        except (ValueError, UnicodeError):
            continue
        raise ValueError("合成统计拒绝断言未生效")
    with patch("builtins.print") as output:
        publish_report(valid)
    assert output.call_count == 482
    assert all(call.args[0].startswith(PREFIX.decode("ascii")) for call in output.call_args_list)
    assert all("private synthetic diagnostic" not in call.args[0] for call in output.call_args_list)
    with patch("builtins.print") as output:
        try:
            publish_report(valid[:-1])
        except ValueError:
            pass
        else:
            raise ValueError("发布边界未拒绝半份报告")
        assert output.call_count == 0
    return len(cases) + 1
