#!/usr/bin/env python3
"""One-shot acceptance driver for the ``verify`` Compose service.

Order of operations (mirrors the acceptance contract):

1. grammar engine + storage unit tests,
2. (image build happens before this container starts -- ``compose up
   --build``),
3. HTTP smoke against the running arbiter:
   unique acceptance, ambiguous acceptance with two stable trees,
   non-consuming-cycle rejection, equivalent retransmission replay,
   audit-id conflict preserving the original evidence,
4. restart the arbiter **keeping its data volume** (after seeding two
   legacy records whose on-disk evidence was stripped) and verify:
   reads return full trees, semantically equivalent retransmissions
   replay with full trees and stable production sequences, conflicts
   still return the original evidence, and the legacy records are
   recovered to complete reviewable conclusions with unchanged audit id,
   fingerprint and seal timestamp,
5. restart a second time and confirm the recovered evidence stayed
   persisted.

Exits 0 only when every step passes; any failure exits 1.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid

BASE_URL = os.environ.get("ARBITER_BASE_URL", "http://127.0.0.1:8080")
HEALTH_TIMEOUT = float(os.environ.get("HEALTH_TIMEOUT", "60"))
VERIFY_IMAGE = os.environ.get("VERIFY_IMAGE", "forest-arbiter-verify:local")
LOCAL_PIDFILE = os.environ.get("LOCAL_PIDFILE", "/tmp/arbiter.pid")

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
    try:
        with urllib.request.urlopen(BASE_URL + path, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


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


# ---------------------------------------------------------------------------
# Tree structure checks (node-by-node reviewability)
# ---------------------------------------------------------------------------


def leaves_cover(node, length):
    """Return True iff the tree tiles tokens [0, length) without gaps."""
    if not isinstance(node, dict):
        return False

    def walk(nd):
        if "token" in nd:
            i, j = nd.get("span", [None, None])
            return [(i, j)] if isinstance(i, int) and j == i + 1 else []
        kids = nd.get("children")
        if not isinstance(kids, list) or not kids:
            return []
        spans = []
        for k in kids:
            spans.extend(walk(k))
        return spans

    spans = walk(node)
    return (
        spans == [(i, i + 1) for i in range(length)]
        and node.get("span") == [0, length]
    )


def check_complete_unique(conclusion, seq, n, msg_prefix):
    tree = conclusion.get("tree")
    ok = (
        conclusion.get("verdict") == "UNIQUE_ACCEPTED"
        and isinstance(tree, dict)
        and tree.get("span") == [0, n]
        and conclusion.get("production_sequence") == seq
        and leaves_cover(tree, n)
        and "archived_tree" not in conclusion
    )
    check(ok, f"{msg_prefix}：完整唯一树（跨度 [0,{n}]、词元逐节点覆盖、"
              f"稳定序列 {seq}）")
    return tree


def check_complete_ambiguous(conclusion, n, msg_prefix, expect_seqs=None):
    trees = conclusion.get("trees") or {}
    seqs = conclusion.get("production_sequences") or {}
    first, second = trees.get("first"), trees.get("second")
    s1, s2 = seqs.get("first"), seqs.get("second")
    ok = (
        conclusion.get("verdict") == "AMBIGUOUS_ACCEPTED"
        and isinstance(first, dict) and isinstance(second, dict)
        and first.get("span") == [0, n] and second.get("span") == [0, n]
        and leaves_cover(first, n) and leaves_cover(second, n)
        and first != second
        and isinstance(s1, list) and isinstance(s2, list) and s1 != s2
        and s1 <= s2
        and "archived_witnesses" not in conclusion
    )
    check(ok, f"{msg_prefix}：两棵完整且不同的见证树（跨度 [0,{n}]、"
              f"词元逐节点覆盖、first/second 序列稳定：{s1} / {s2}）")
    if expect_seqs is not None:
        check(seqs == expect_seqs,
              f"{msg_prefix}：产生式编号序列与首次结论一致 {expect_seqs}")
    return first, second, seqs


# ---------------------------------------------------------------------------
# Restart orchestration (Compose sibling container or local fallback)
# ---------------------------------------------------------------------------


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def docker_available():
    if not shutil.which("docker"):
        return False
    return _run(["docker", "info"]).returncode == 0


def arbiter_container():
    out = _run([
        "docker", "ps", "-q",
        "--filter", "label=com.docker.compose.service=arbiter",
    ])
    cid = out.stdout.strip().splitlines()[0] if out.stdout.strip() else ""
    if not cid:  # fallback: any running forest-arbiter image
        out = _run(["docker", "ps", "-q", "--filter",
                    "ancestor=forest-arbiter:local"])
        cid = out.stdout.strip().splitlines()[0] if out.stdout.strip() else ""
    return cid


def arbiter_data_volume(cid):
    out = _run(["docker", "inspect", "-f",
                "{{range .Mounts}}{{if eq .Destination \"/data\"}}"
                "{{.Name}}{{end}}{{end}}", cid])
    return out.stdout.strip()


def seed_legacy_docker(volume):
    return _run([
        "docker", "run", "--rm",
        "-v", f"{volume}:/data",
        "-e", "ARBITER_STORE=/data/sealed.json",
        "--entrypoint", "python3",
        VERIFY_IMAGE, "scripts/seed_legacy.py",
    ])


def restart_docker_arbiter(seed):
    cid = arbiter_container()
    if not cid:
        check(False, "未找到运行中的 arbiter 容器，无法执行保卷重启")
        return False
    volume = arbiter_data_volume(cid)
    check(bool(volume), f"识别 arbiter 数据卷：{volume or '<未知>'}")
    # Stop first so the volume has a single writer while the legacy
    # records are injected; start afterwards to trigger recovery on load.
    r = _run(["docker", "stop", cid])
    check(r.returncode == 0, f"停止 arbiter 容器 {cid[:12]}（保留数据卷）")
    if r.returncode != 0:
        return False
    if seed and volume:
        r = seed_legacy_docker(volume)
        check(r.returncode == 0,
              f"向停服后的数据卷注入旧格式封存记录（{r.stdout.strip()}）")
        if r.returncode != 0:
            print(r.stderr)
            return False
    r = _run(["docker", "start", cid])
    check(r.returncode == 0, f"重新启动 arbiter 容器 {cid[:12]}")
    return r.returncode == 0 and wait_healthy()


def restart_local_arbiter(seed):
    """Local fallback: restart the subprocess started by entrypoint.sh."""
    if not os.path.exists(LOCAL_PIDFILE):
        check(False, f"本地回退缺少 pidfile {LOCAL_PIDFILE}，无法重启")
        return False
    with open(LOCAL_PIDFILE) as fh:
        pid = int(fh.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.2)
    if seed:
        r = _run([sys.executable, "scripts/seed_legacy.py"],
                 env={**os.environ,
                      "ARBITER_STORE": "/tmp/arbiter-data/sealed.json"})
        check(r.returncode == 0,
              f"向本地数据目录注入旧格式封存记录（{r.stdout.strip()}）")
        if r.returncode != 0:
            print(r.stderr)
            return False
    log = open("/tmp/arbiter.log", "ab")
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.service"],
        stdout=log, stderr=log,
        env={**os.environ, "ARBITER_STORE": "/tmp/arbiter-data/sealed.json",
             "ARBITER_PORT": "18080"},
    )
    with open(LOCAL_PIDFILE, "w") as fh:
        fh.write(str(proc.pid))
    print(f"    本地 arbiter 已重启 pid={proc.pid}")
    return wait_healthy()


def restart_arbiter(seed=False):
    if docker_available():
        return restart_docker_arbiter(seed)
    if os.environ.get("ALLOW_LOCAL_FALLBACK") == "1":
        return restart_local_arbiter(seed)
    check(False, "既无 Docker daemon 也未启用 ALLOW_LOCAL_FALLBACK，无法重启")
    return False


# ---------------------------------------------------------------------------
# Scenario payloads
# ---------------------------------------------------------------------------


UNIQUE_PAYLOAD = {
    "nonterminals": ["S"],
    "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
    "start": "S",
    "tokens": ["a", "b"],
}

AMBIGUOUS_PAYLOAD = {
    "nonterminals": ["E"],
    "productions": [
        {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
        {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
        {"id": 3, "lhs": "E", "rhs": ["id"]},
    ],
    "start": "E",
    "tokens": ["id", "+", "id", "*", "id"],
}

LEGACY_UNIQUE = "legacy-unique-restore"
LEGACY_AMB = "legacy-amb-restore"


def main() -> int:
    step("步骤 1/6：文法引擎与封存存储单元测试")
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

    step("步骤 2/6：唯一接受场景（首次响应含完整唯一树）")
    uid = f"verify-unique-{run_id}"
    status, body = http_post("/api/v1/analyze",
                             {"audit_id": uid, **UNIQUE_PAYLOAD})
    check(status == 200, f"HTTP 200（实际 {status}）")
    res = body.get("result", {})
    check(body.get("seal_status") == "SEALED", "首次提交封存 SEALED")
    check_complete_unique(res, [1], 2, "首次响应")
    unique_sealed_at = body.get("sealed_at")
    unique_hash = body.get("request_hash")

    # Equivalent retransmission (identical content) -> replay.
    status2, body2 = http_post("/api/v1/analyze",
                               {"audit_id": uid, **UNIQUE_PAYLOAD})
    check(status2 == 200 and body2.get("seal_status") == "REPLAYED",
          f"语义等价重放回封存结论 REPLAYED（实际 HTTP {status2} "
          f"{body2.get('seal_status')}）")
    check_complete_unique(body2.get("result", {}), [1], 2, "等价重传")

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
          and isinstance(orig.get("tree"), dict)
          and orig.get("tree", {}).get("span") == [0, 2],
          "冲突响应保留并回传完整原始证据（含唯一树）")

    step("步骤 3/6：歧义接受场景（两棵稳定选出的完整树）")
    aid = f"verify-amb-{run_id}"
    status, body = http_post("/api/v1/analyze",
                             {"audit_id": aid, **AMBIGUOUS_PAYLOAD})
    check(status == 200 and
          body.get("result", {}).get("verdict") == "AMBIGUOUS_ACCEPTED",
          f"歧义接受（实际 HTTP {status} "
          f"{body.get('result', {}).get('verdict')}）")
    _, _, amb_seqs = check_complete_ambiguous(
        body.get("result", {}), 5, "首次响应")
    amb_sealed_at = body.get("sealed_at")
    amb_hash = body.get("request_hash")

    # Determinism: shuffled declaration/production order, new id.
    shuffled = copy.deepcopy(AMBIGUOUS_PAYLOAD)
    shuffled["productions"] = list(reversed(shuffled["productions"]))
    status_b, body_b = http_post("/api/v1/analyze", {
        "audit_id": f"verify-amb2-{run_id}", **shuffled})
    sb = body_b.get("result", {}).get("production_sequences", {})
    check(sb.get("first") == amb_seqs["first"]
          and sb.get("second") == amb_seqs["second"],
          f"产生式声明顺序打乱后选树仍稳定：{sb.get('first')} == "
          f"{amb_seqs['first']}")

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

    # ------------------------------------------------------------------
    step("步骤 4/6：保留数据卷重启（并注入旧格式不完整封存）")
    if not restart_arbiter(seed=True):
        return report()

    step("步骤 5/6：重启后读取、等价重传、冲突与旧记录恢复")
    # Reads by audit id return complete trees.
    s, b = http_get(f"/api/v1/conclusion/{uid}")
    check(s == 200, f"GET 唯一结论 200（实际 {s}）")
    concl = b.get("conclusion", {})
    check(b.get("sealed_at") == unique_sealed_at
          and b.get("request_hash") == unique_hash,
          "重启后读取：审计标识、请求指纹、封存时间不变")
    check_complete_unique(concl, [1], 2, "重启后读取唯一结论")

    s, b = http_get(f"/api/v1/conclusion/{aid}")
    check(s == 200, f"GET 歧义结论 200（实际 {s}）")
    check(b.get("sealed_at") == amb_sealed_at
          and b.get("request_hash") == amb_hash,
          "重启后读取：歧义记录审计标识、指纹、封存时间不变")
    check_complete_ambiguous(b.get("conclusion", {}), 5,
                             "重启后读取歧义结论", amb_seqs)

    # Semantically equivalent retransmission after restart (productions
    # declared in a different order) replays with complete evidence.
    s, b = http_post("/api/v1/analyze",
                     {"audit_id": uid, **UNIQUE_PAYLOAD})
    check(s == 200 and b.get("seal_status") == "REPLAYED",
          f"重启后等价重传 REPLAYED（实际 HTTP {s} "
          f"{b.get('seal_status')}）")
    check_complete_unique(b.get("result", {}), [1], 2, "重启后等价重传唯一")

    s, b = http_post("/api/v1/analyze",
                     {"audit_id": aid, **shuffled})
    check(s == 200 and b.get("seal_status") == "REPLAYED",
          f"重启后歧义文法异序等价重传 REPLAYED（实际 HTTP {s}）")
    check_complete_ambiguous(b.get("result", {}), 5,
                             "重启后等价重传歧义", amb_seqs)

    # Conflict still enforced after restart, original evidence complete.
    s, b = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["x"]}],
        "start": "S",
        "tokens": ["x"],
    })
    check(s == 409 and b.get("error") == "AUDIT_ID_CONFLICT",
          f"重启后同标识不同输入仍冲突 HTTP 409（实际 {s}）")
    orig = b.get("original_evidence", {}).get("conclusion", {})
    check(isinstance(orig.get("tree"), dict)
          and orig["tree"].get("span") == [0, 2],
          "重启后冲突仍回传完整原始证据")

    # Legacy records recovered from frozen input.
    s, b = http_get(f"/api/v1/conclusion/{LEGACY_UNIQUE}")
    check(s == 200, f"GET 旧格式唯一记录 200（实际 {s}）")
    check(b.get("sealed_at") == "2025-12-31T23:59:00Z",
          f"恢复记录封存时间不变（实际 {b.get('sealed_at')}）")
    check_complete_unique(b.get("conclusion", {}), [5], 2,
                          "旧格式唯一记录安全恢复")

    s, b = http_get(f"/api/v1/conclusion/{LEGACY_AMB}")
    check(s == 200, f"GET 旧格式歧义记录 200（实际 {s}）")
    check(b.get("sealed_at") == "2025-12-31T23:59:01Z",
          f"恢复记录封存时间不变（实际 {b.get('sealed_at')}）")
    _, _, legacy_seqs = check_complete_ambiguous(
        b.get("conclusion", {}), 5, "旧格式歧义记录安全恢复")
    # The recovered record is itself replay-stable.
    legacy_payload = copy.deepcopy(AMBIGUOUS_PAYLOAD)
    legacy_payload["productions"] = [
        {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
        {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
        {"id": 4, "lhs": "E", "rhs": ["id"]},
    ]
    s, b = http_post("/api/v1/analyze",
                     {"audit_id": LEGACY_AMB, **legacy_payload})
    check(s == 200 and b.get("seal_status") == "REPLAYED",
          f"恢复记录等价重传 REPLAYED（实际 HTTP {s}）")
    check_complete_ambiguous(b.get("result", {}), 5,
                             "恢复记录等价重传", legacy_seqs)

    # ------------------------------------------------------------------
    step("步骤 6/6：再次重开确认恢复结果已持久化")
    if not restart_arbiter(seed=False):
        return report()

    for label, audit_id, kind, n, seq in (
        ("唯一", uid, "U", 2, [1]),
        ("歧义", aid, "A", 5, None),
        ("旧唯一", LEGACY_UNIQUE, "U", 2, [5]),
        ("旧歧义", LEGACY_AMB, "A", 5, None),
    ):
        s, b = http_get(f"/api/v1/conclusion/{audit_id}")
        check(s == 200, f"二次重开 GET {label} 结论 200（实际 {s}）")
        if kind == "U":
            check_complete_unique(b.get("conclusion", {}), seq, n,
                                  f"二次重开{label}结论")
        else:
            check_complete_ambiguous(b.get("conclusion", {}), n,
                                     f"二次重开{label}结论")
    s, b = http_get(f"/api/v1/conclusion/{LEGACY_UNIQUE}")
    check(b.get("sealed_at") == "2025-12-31T23:59:00Z",
          "二次重开后恢复记录封存时间仍不变")

    return report()


def report() -> int:
    print("\n================ 验收汇总 ================")
    if failures:
        print(f"失败 {len(failures)} 项：")
        for f in failures:
            print(f"  - {f}")
        print("RESULT: FAIL")
        return 1
    print("全部步骤通过：单元测试 / 唯一 / 歧义 / 无消费环 / 回放 / 冲突 / "
          "保卷重启读取与等价重传 / 旧记录恢复 / 二次重开持久化")
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
