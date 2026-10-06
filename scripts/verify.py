#!/usr/bin/env python3
"""One-shot acceptance driver for the ``verify`` Compose service.

Order of operations (mirrors the acceptance contract):

1. grammar engine + storage unit tests,
2. (image build happens before this container starts -- ``compose up
   --build``),
3. HTTP smoke against the running arbiter:
   unique acceptance, ambiguous acceptance with two stable trees,
   non-consuming-cycle rejection, equivalent retransmission replay,
   audit-id conflict preserving the original evidence.

Exits 0 only when every step passes; any failure exits 1.
"""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid

BASE_URL = os.environ.get("ARBITER_BASE_URL", "http://127.0.0.1:8080")
HEALTH_TIMEOUT = float(os.environ.get("HEALTH_TIMEOUT", "30"))

failures = []


def step(name):
    print(f"\n--- {name}", flush=True)


def check(cond, msg):
    if cond:
        print(f"    PASS: {msg}")
    else:
        print(f"    FAIL: {msg}")
        failures.append(msg)


def http_post(path, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL + path, data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def http_get(path):
    with urllib.request.urlopen(BASE_URL + path, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def wait_healthy():
    deadline = time.time() + HEALTH_TIMEOUT
    last = None
    while time.time() < deadline:
        try:
            status, body = http_get("/healthz")
            if status == 200 and body.get("status") == "ok":
                print(f"    PASS: 健康检查 200 {body}")
                return True
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.5)
    print(f"    FAIL: 健康检查超时（{HEALTH_TIMEOUT}s）：{last}")
    failures.append("health")
    return False


def main() -> int:
    step("步骤 1/3：文法引擎与封存存储单元测试")
    if os.environ.get("SKIP_UNIT_TESTS") == "1":
        print("    （单元测试已在本阶段之外执行，跳过）")
    else:
        loader = unittest.TestLoader()
        suite = loader.discover("tests", pattern="test_*.py")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not result.wasSuccessful():
            failures.append("unit tests")
            # Still report early; HTTP smoke is meaningless without engine.
            return report()

    if not wait_healthy():
        return report()

    run_id = uuid.uuid4().hex[:8]

    step("步骤 2/3：唯一接受场景（唯一树）")
    uid = f"verify-unique-{run_id}"
    status, body = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "start": "S",
        "tokens": ["a", "b"],
    })
    check(status == 200, f"HTTP 200（实际 {status}）")
    res = body.get("result", {})
    check(res.get("verdict") == "UNIQUE_ACCEPTED",
          f"verdict=UNIQUE_ACCEPTED（实际 {res.get('verdict')}）")
    check(res.get("production_sequence") == [1],
          f"唯一产生式序列 [1]（实际 {res.get('production_sequence')}）")
    check(body.get("seal_status") == "SEALED", "首次提交封存 SEALED")
    tree = res.get("tree", {})
    check(tree.get("symbol") == "S" and tree.get("span") == [0, 2]
          and len(tree.get("children", [])) == 2,
          "返回唯一派生树且跨度覆盖全部词元")

    # Equivalent retransmission (declaration order shuffled) -> replay.
    status2, body2 = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "start": "S",
        "tokens": ["a", "b"],
    })
    check(status2 == 200 and body2.get("seal_status") == "REPLAYED",
          f"语义等价重放回封存结论 REPLAYED（实际 HTTP {status2} {body2.get('seal_status')}）")
    check(body2.get("result", {}).get("production_sequence") == [1],
          "回放的证据与原结论一致")

    # Same audit id, different input -> 409 conflict, evidence retained.
    status3, body3 = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
        "start": "S",
        "tokens": ["a"],
    })
    check(status3 == 409 and body3.get("error") == "AUDIT_ID_CONFLICT",
          f"同标识不同输入冲突 HTTP 409（实际 {status3}）")
    orig = body3.get("original_evidence", {}).get("conclusion", {})
    check(orig.get("verdict") == "UNIQUE_ACCEPTED"
          and orig.get("production_sequence") == [1],
          "冲突响应保留并回传原始证据")

    step("步骤 3a：歧义接受场景（两棵按编号序列稳定选出的树）")
    aid = f"verify-amb-{run_id}"
    status, body = http_post("/api/v1/analyze", {
        "audit_id": aid,
        "nonterminals": ["E"],
        "productions": [
            {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
            {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
            {"id": 3, "lhs": "E", "rhs": ["id"]},
        ],
        "start": "E",
        "tokens": ["id", "+", "id", "*", "id"],
    })
    res = body.get("result", {})
    check(status == 200 and res.get("verdict") == "AMBIGUOUS_ACCEPTED",
          f"歧义接受（实际 HTTP {status} {res.get('verdict')}）")
    seqs = res.get("production_sequences", {})
    s1, s2 = seqs.get("first"), seqs.get("second")
    check(isinstance(s1, list) and isinstance(s2, list) and s1 != s2,
          f"两棵树产生式序列不同：{s1} vs {s2}")
    check(s1 == sorted([s1, s2])[0],
          f"first 为编号序列字典序最小：{s1} <= {s2}")
    first, second = res.get("trees", {}).values() if res.get("trees") else ({}, {})
    check(first.get("span") == [0, 5] and second.get("span") == [0, 5],
          "两棵不同派生树均完整覆盖输入 [0,5]")
    # Determinism: re-submit under a new id and compare tree sequences.
    status_b, body_b = http_post("/api/v1/analyze", {
        "audit_id": f"verify-amb2-{run_id}",
        "nonterminals": ["E"],
        "productions": [
            {"id": 3, "lhs": "E", "rhs": ["id"]},
            {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
            {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
        ],
        "start": "E",
        "tokens": ["id", "+", "id", "*", "id"],
    })
    sb = body_b.get("result", {}).get("production_sequences", {})
    check(sb.get("first") == s1 and sb.get("second") == s2,
          f"产生式提交顺序打乱后选树仍稳定：{sb.get('first')} == {s1}")

    step("步骤 3b：可达不消费词元循环必须明确拒绝")
    cid = f"verify-cycle-{run_id}"
    status, body = http_post("/api/v1/analyze", {
        "audit_id": cid,
        "nonterminals": ["A", "B"],
        "productions": [
            {"id": 1, "lhs": "A", "rhs": ["B"]},
            {"id": 2, "lhs": "B", "rhs": ["A"]},
            {"id": 3, "lhs": "A", "rhs": []},
        ],
        "start": "A",
        "tokens": [],
    })
    res = body.get("result", {})
    rej = res.get("rejection", {})
    check(status == 200 and res.get("verdict") == "REJECTED",
          f"循环场景 REJECTED（实际 HTTP {status} {res.get('verdict')}）")
    check(rej.get("reason") == "NONCONSUMING_CYCLE",
          f"原因为 NONCONSUMING_CYCLE（实际 {rej.get('reason')}）")
    cyc = rej.get("evidence", {}).get("cycle")
    check(cyc == ["A", "B", "A"], f"给出循环证据 {cyc}")
    check("无限" in rej.get("detail", "") or "循环" in rej.get("detail", ""),
          "给出首个可操作中文原因")

    return report()


def report() -> int:
    print("\n================ 验收汇总 ================")
    if failures:
        print(f"失败 {len(failures)} 项：")
        for f in failures:
            print(f"  - {f}")
        print("RESULT: FAIL")
        return 1
    print("全部步骤通过：单元测试 / 镜像 / 唯一 / 歧义 / 无消费环 / 回放 / 冲突")
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
