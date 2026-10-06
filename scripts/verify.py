#!/usr/bin/env python3
"""One-shot acceptance driver for the ``verify`` Compose service.

Order of operations (mirrors the acceptance contract):

1. grammar engine + storage unit tests,
2. (image build happens before this container starts -- ``compose up
   --build``),
3. HTTP smoke against the running arbiter: unique acceptance (full
   tree), ambiguous acceptance (two stable witness trees),
   non-consuming-cycle rejection, equivalent retransmission replay,
   audit-id conflict preserving the original evidence,
4. restart the arbiter over the SAME data volume and confirm reads by
   audit id and equivalent retransmissions still return the complete
   evidence (full trees + stable production-id sequences), that
   rejections are unchanged and that conflicts still return the
   original evidence,
5. seed a pre-fix store file (accept evidence archived without trees),
   restart, and confirm the legacy entries are safely recovered from
   their frozen inputs -- audit ids, request fingerprints and seal
   timestamps unchanged -- and that the recovered evidence persists
   across yet another restart.

Exits 0 only when every step passes; any failure exits 1.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

BASE_URL = os.environ.get("ARBITER_BASE_URL", "http://127.0.0.1:8080")
HEALTH_TIMEOUT = float(os.environ.get("HEALTH_TIMEOUT", "30"))

# Local-fallback restart hints (exported by scripts/entrypoint.sh when no
# Docker daemon is available); in Compose the arbiter container is
# discovered through the mounted docker socket instead.
LOCAL_FALLBACK = os.environ.get("ARBITER_LOCAL_FALLBACK") == "1"
LOCAL_STORE = os.environ.get("ARBITER_LOCAL_STORE", "")
LOCAL_PORT = os.environ.get("ARBITER_LOCAL_PORT", "18080")
LOCAL_PIDFILE = os.environ.get("ARBITER_LOCAL_PIDFILE", "/tmp/arbiter.pid")

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
# Node-by-node review of derivation-tree evidence
# ---------------------------------------------------------------------------


def tree_problems(node, payload, path="root"):
    """Review a tree against the frozen request; returns a list of problems.

    Every internal node must carry symbol/production/span consistent with
    the declared production, children must tile the parent span, and the
    leaves must cover the input tokens exactly once, in order.
    """
    prods = {p["id"]: p for p in payload["productions"]}
    tokens = payload["tokens"]
    problems = []

    def rec(n, where, lo, hi):
        if not isinstance(n, dict):
            problems.append(f"{where}: 节点不是对象")
            return []
        if "token" in n:
            span, tok = n.get("span"), n.get("token")
            if not (isinstance(span, list) and len(span) == 2
                    and all(isinstance(x, int) for x in span)
                    and span[1] == span[0] + 1):
                problems.append(f"{where}: 词元节点跨度非法 {span!r}")
                return []
            if [span[0], span[1]] != [lo, hi]:
                problems.append(f"{where}: 词元跨度 {span} 与期望 [{lo},{hi}] 不符")
            if not (0 <= span[0] < len(tokens)) or tokens[span[0]] != tok:
                problems.append(
                    f"{where}: 词元 {tok!r} 与输入位置 {span[0]} 的词元不符")
            return [(span[0], tok)]
        sym, pid, span = n.get("symbol"), n.get("production"), n.get("span")
        kids = n.get("children")
        if not isinstance(sym, str):
            problems.append(f"{where}: 缺少 symbol 字段")
        if not (isinstance(span, list) and len(span) == 2
                and all(isinstance(x, int) for x in span)
                and 0 <= span[0] <= span[1] <= len(tokens)):
            problems.append(f"{where}: 内部节点跨度非法 {span!r}")
            return []
        if [span[0], span[1]] != [lo, hi]:
            problems.append(f"{where}: 跨度 {span} 与期望 [{lo},{hi}] 不符")
        prod = prods.get(pid)
        if prod is None:
            problems.append(f"{where}: 未知产生式编号 {pid!r}")
            return []
        if prod["lhs"] != sym:
            problems.append(
                f"{where}: 产生式 {pid} 左部 {prod['lhs']!r} 与节点符号 {sym!r} 不符")
        rhs = prod["rhs"]
        if not isinstance(kids, list) or len(kids) != len(rhs):
            problems.append(
                f"{where}: 子节点数量与产生式 {pid} 右部长度 {len(rhs)} 不符")
            return []
        leaves = []
        pos = span[0]
        for idx, (child, rsym) in enumerate(zip(kids, rhs)):
            cwhere = f"{where}/{idx}"
            if "token" in child:
                if child.get("token") != rsym:
                    problems.append(
                        f"{cwhere}: 词元 {child.get('token')!r} 与右部符号 {rsym!r} 不符")
                leaves += rec(child, cwhere, pos, pos + 1)
                pos += 1
            else:
                if child.get("symbol") != rsym:
                    problems.append(
                        f"{cwhere}: 子符号 {child.get('symbol')!r} 与右部符号 {rsym!r} 不符")
                cspan = child.get("span")
                chi = (cspan[1] if isinstance(cspan, list) and len(cspan) == 2
                       and isinstance(cspan[1], int) else hi)
                leaves += rec(child, cwhere, pos, chi)
                pos = chi
        if pos != span[1]:
            problems.append(
                f"{where}: 子节点终点 {pos} 与节点跨度终点 {span[1]} 不符")
        return leaves

    leaves = rec(node, path, 0, len(tokens))
    if sorted(leaves) != [(i, t) for i, t in enumerate(tokens)]:
        problems.append(f"{path}: 叶节点未按序精确覆盖全部输入词元")
    return problems


def preorder_pids(node):
    """Preorder production-id sequence of a concrete evidence tree."""
    if "token" in node:
        return []
    out = [node.get("production")]
    for child in node.get("children", []):
        out += preorder_pids(child)
    return out


def report_tree(node, payload, where):
    problems = tree_problems(node, payload)
    if problems:
        check(False, f"{where}：树证据问题：{'; '.join(problems[:3])}")
    else:
        check(True, f"{where}：逐节点复核通过（跨度/产生式/子结构/词元覆盖）")


def expect_unique_evidence(conclusion, payload, where):
    check(conclusion.get("verdict") == "UNIQUE_ACCEPTED",
          f"{where}：verdict=UNIQUE_ACCEPTED（实际 {conclusion.get('verdict')}）")
    check(isinstance(conclusion.get("production_sequence"), list)
          and len(conclusion["production_sequence"]) >= 1,
          f"{where}：包含稳定产生式编号序列 {conclusion.get('production_sequence')}")
    tree = conclusion.get("tree")
    if not isinstance(tree, dict):
        check(False, f"{where}：缺少唯一派生树 tree")
        return
    check(tree.get("span") == [0, len(payload["tokens"])],
          f"{where}：唯一树根跨度覆盖全部输入 {tree.get('span')}")
    report_tree(tree, payload, f"{where}：唯一树")
    check(preorder_pids(tree) == conclusion.get("production_sequence"),
          f"{where}：树先序编号序列与 production_sequence 一致")


def expect_ambiguous_evidence(conclusion, payload, where, expect_seqs=None):
    check(conclusion.get("verdict") == "AMBIGUOUS_ACCEPTED",
          f"{where}：verdict=AMBIGUOUS_ACCEPTED（实际 {conclusion.get('verdict')}）")
    seqs = conclusion.get("production_sequences", {})
    s1, s2 = seqs.get("first"), seqs.get("second")
    check(isinstance(s1, list) and isinstance(s2, list) and s1 != s2,
          f"{where}：两条不同的稳定产生式编号序列：{s1} vs {s2}")
    if isinstance(s1, list) and isinstance(s2, list):
        check(s1 == sorted([s1, s2])[0],
              f"{where}：first 为字典序最小序列：{s1} <= {s2}")
    if expect_seqs is not None:
        check([s1, s2] == [expect_seqs["first"], expect_seqs["second"]],
              f"{where}：编号序列与首次封存一致（稳定）：{s1}, {s2}")
    trees = conclusion.get("trees")
    if not (isinstance(trees, dict)
            and isinstance(trees.get("first"), dict)
            and isinstance(trees.get("second"), dict)):
        check(False, f"{where}：缺少两棵歧义见证树 trees.first/trees.second")
        return {"first": s1, "second": s2}
    first, second = trees["first"], trees["second"]
    check(first != second, f"{where}：两棵见证树结构不同")
    for which, tree in (("first", first), ("second", second)):
        check(tree.get("span") == [0, len(payload["tokens"])],
              f"{where}：{which} 树根跨度覆盖全部输入 {tree.get('span')}")
        report_tree(tree, payload, f"{where}：{which} 树")
    check(preorder_pids(first) == s1 and preorder_pids(second) == s2,
          f"{where}：两棵树的先序编号序列与 production_sequences 一致")
    return {"first": s1, "second": s2}


# ---------------------------------------------------------------------------
# Restarting the arbiter over its unchanged data volume
# ---------------------------------------------------------------------------

_LOCAL_PROC = None
_ARB_CONTAINER = None


def _docker():
    exe = shutil.which("docker")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "info"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
    except Exception:  # noqa: BLE001
        return None
    return exe if r.returncode == 0 else None


def arbiter_container():
    """Compose container id of the arbiter service (same project as us)."""
    global _ARB_CONTAINER
    if _ARB_CONTAINER:
        return _ARB_CONTAINER
    exe = _docker()
    if not exe:
        return None

    def run(args):
        return subprocess.run([exe] + args, capture_output=True, text=True,
                              timeout=30)

    project = ""
    try:
        r = run(["inspect", socket.gethostname(), "--format",
                 "{{ index .Config.Labels \"com.docker.compose.project\" }}"])
        if r.returncode == 0:
            project = r.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    filters = ["--filter", "label=com.docker.compose.service=arbiter"]
    if project:
        filters += ["--filter", f"label=com.docker.compose.project={project}"]
    try:
        r = run(["ps", "-q"] + filters)
        ids = r.stdout.split() if r.returncode == 0 else []
    except Exception:  # noqa: BLE001
        ids = []
    _ARB_CONTAINER = ids[0] if ids else None
    return _ARB_CONTAINER


def _restart_local():
    global _LOCAL_PROC
    if _LOCAL_PROC is not None and _LOCAL_PROC.poll() is None:
        _LOCAL_PROC.terminate()
        try:
            _LOCAL_PROC.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _LOCAL_PROC.kill()
    else:
        try:
            with open(LOCAL_PIDFILE, encoding="utf-8") as fh:
                os.kill(int(fh.read().strip()), signal.SIGTERM)
        except Exception:  # noqa: BLE001
            pass
    # Wait until the old listener is gone before rebinding the port.
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            urllib.request.urlopen(BASE_URL + "/healthz", timeout=1)
        except Exception:  # noqa: BLE001
            break
        time.sleep(0.2)
    env = dict(os.environ)
    env["ARBITER_HOST"] = "127.0.0.1"
    env["ARBITER_PORT"] = str(LOCAL_PORT)
    env["ARBITER_STORE"] = LOCAL_STORE
    with open("/tmp/arbiter.log", "ab") as log:
        _LOCAL_PROC = subprocess.Popen(
            [sys.executable, "-m", "app.service"], cwd=REPO_ROOT, env=env,
            stdout=log, stderr=log)
    try:
        with open(LOCAL_PIDFILE, "w", encoding="utf-8") as fh:
            fh.write(str(_LOCAL_PROC.pid))
    except Exception:  # noqa: BLE001
        pass
    return wait_healthy()


def restart_arbiter():
    """Restart the service; the Compose data volume stays untouched."""
    if LOCAL_FALLBACK:
        return _restart_local()
    exe = _docker()
    cid = arbiter_container() if exe else None
    if not cid:
        check(False, "无法定位 arbiter 容器（需要挂载 docker.sock 或本地回退模式）")
        return False
    try:
        r = subprocess.run([exe, "restart", cid], capture_output=True,
                           text=True, timeout=120)
    except Exception as exc:  # noqa: BLE001
        check(False, f"重启 arbiter 容器失败：{exc}")
        return False
    if r.returncode != 0:
        check(False, f"docker restart 失败：{r.stderr.strip()}")
        return False
    print(f"    PASS: 已重启 arbiter 容器 {cid[:12]}（数据卷保持不变）")
    return wait_healthy()


_SEED_SCRIPT = (
    "import json, os, sys\n"
    "store = os.environ.get('ARBITER_STORE', '/data/sealed.json')\n"
    "new = json.loads(sys.argv[1])\n"
    "try:\n"
    "    with open(store, encoding='utf-8') as fh:\n"
    "        data = json.load(fh)\n"
    "    if not isinstance(data, dict):\n"
    "        data = {}\n"
    "except Exception:\n"
    "    data = {}\n"
    "data.update(new)\n"
    "tmp = store + '.tmp'\n"
    "with open(tmp, 'w', encoding='utf-8') as fh:\n"
    "    json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)\n"
    "os.replace(tmp, store)\n"
    "print('seeded', len(new))\n"
)


def seed_store_entries(entries):
    """Merge raw entries into the sealed store file (legacy fixture)."""
    if LOCAL_FALLBACK:
        data = {}
        if os.path.exists(LOCAL_STORE):
            try:
                with open(LOCAL_STORE, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:  # noqa: BLE001
                data = {}
        data.update(entries)
        tmp = LOCAL_STORE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, LOCAL_STORE)
        return True
    exe = _docker()
    cid = arbiter_container() if exe else None
    if not cid:
        check(False, "无法定位 arbiter 容器以注入遗留封存数据")
        return False
    try:
        r = subprocess.run(
            [exe, "exec", cid, "python3", "-c", _SEED_SCRIPT,
             json.dumps(entries, ensure_ascii=False)],
            capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001
        check(False, f"注入遗留封存数据失败：{exc}")
        return False
    if r.returncode != 0:
        check(False, f"注入遗留封存数据失败：{r.stderr.strip()}")
        return False
    print(f"    PASS: 已注入 {len(entries)} 条遗留封存记录（{r.stdout.strip()}）")
    return True


# ---------------------------------------------------------------------------
# Legacy (pre-fix) store fixture
# ---------------------------------------------------------------------------

LEGACY_SEALED_AT = "2025-12-01T00:00:00Z"


def make_legacy_entry(payload):
    """Build a store entry in the pre-fix format (tree evidence stripped).

    The conclusion is computed by the current deterministic engine and
    then archived exactly the way the old revision persisted it, so the
    recovery under test must reproduce this very evidence.
    """
    from app.service import _compute
    from app.storage import canonical_fingerprint

    request_hash, canonical = canonical_fingerprint(payload)
    conclusion = _compute(payload)
    archived = json.loads(json.dumps(conclusion))
    if archived["verdict"] == "UNIQUE_ACCEPTED":
        archived.pop("tree", None)
        archived["archived_tree"] = True
    elif archived["verdict"] == "AMBIGUOUS_ACCEPTED":
        trees = archived.pop("trees", None) or {}
        archived["archived_witnesses"] = sorted(trees)
    entry = {
        "audit_id": payload["audit_id"],
        "request_hash": request_hash,
        "canonical_request": canonical,
        "sealed_at": LEGACY_SEALED_AT,
        "conclusion": archived,
    }
    return entry, conclusion


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def unique_payload(audit_id):
    return {
        "audit_id": audit_id,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "start": "S",
        "tokens": ["a", "b"],
    }


def ambiguous_payload(audit_id):
    return {
        "audit_id": audit_id,
        "nonterminals": ["E"],
        "productions": [
            {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
            {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
            {"id": 3, "lhs": "E", "rhs": ["id"]},
        ],
        "start": "E",
        "tokens": ["id", "+", "id", "*", "id"],
    }


def shuffled(payload):
    """Semantically equivalent retransmission: declarations reordered."""
    out = json.loads(json.dumps(payload))
    out["productions"] = list(reversed(out["productions"]))
    return out


def scenario_unique(uid):
    step("步骤 2/6：唯一接受场景（唯一树）")
    payload = unique_payload(uid)
    status, body = http_post("/api/v1/analyze", payload)
    check(status == 200, f"HTTP 200（实际 {status}）")
    check(body.get("seal_status") == "SEALED", "首次提交封存 SEALED")
    res = body.get("result", {})
    expect_unique_evidence(res, payload, "首次响应")
    check(res.get("production_sequence") == [1],
          f"唯一产生式序列 [1]（实际 {res.get('production_sequence')}）")

    # Equivalent retransmission -> replay of the same full evidence.
    status2, body2 = http_post("/api/v1/analyze", shuffled(payload))
    check(status2 == 200 and body2.get("seal_status") == "REPLAYED",
          f"语义等价重放回放原结论 REPLAYED（实际 HTTP {status2} "
          f"{body2.get('seal_status')}）")
    check(body2.get("result") == res, "回放证据与首次响应完全一致（含唯一树）")

    # Same audit id, different input -> 409 conflict, evidence retained.
    conflict = unique_payload(uid)
    conflict["tokens"] = ["a"]
    conflict["productions"] = [{"id": 1, "lhs": "S", "rhs": ["a"]}]
    status3, body3 = http_post("/api/v1/analyze", conflict)
    check(status3 == 409 and body3.get("error") == "AUDIT_ID_CONFLICT",
          f"同标识不同输入冲突 HTTP 409（实际 {status3}）")
    check(body3.get("original_evidence", {}).get("conclusion") == res,
          "冲突响应保留并回传原始证据（含唯一树）")
    return res, body.get("sealed_at"), body.get("request_hash")


def scenario_ambiguous(aid, aid2):
    step("步骤 3/6：歧义接受场景（两棵按编号序列稳定选出的树）")
    payload = ambiguous_payload(aid)
    status, body = http_post("/api/v1/analyze", payload)
    res = body.get("result", {})
    check(status == 200, f"HTTP 200（实际 {status}）")
    seqs = expect_ambiguous_evidence(res, payload, "首次响应")

    # Determinism: same content under a new id, declaration order
    # shuffled, must select the same two sequences.
    status_b, body_b = http_post("/api/v1/analyze", shuffled(ambiguous_payload(aid2)))
    sb = body_b.get("result", {})
    check(status_b == 200 and sb.get("production_sequences") == seqs,
          f"产生式提交顺序打乱后选树仍稳定：{sb.get('production_sequences')}")
    check(sb.get("trees") == res.get("trees"),
          "乱序重提交（新标识）返回相同的两棵见证树")
    return res


def scenario_cycle(cid):
    step("步骤 4/6：可达不消费词元循环必须明确拒绝")
    payload = {
        "audit_id": cid,
        "nonterminals": ["A", "B"],
        "productions": [
            {"id": 1, "lhs": "A", "rhs": ["B"]},
            {"id": 2, "lhs": "B", "rhs": ["A"]},
            {"id": 3, "lhs": "A", "rhs": []},
        ],
        "start": "A",
        "tokens": [],
    }
    status, body = http_post("/api/v1/analyze", payload)
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
    return res


def scenario_after_restart(ctx):
    step("步骤 5/6：保留数据卷重启后，读取与等价重传仍返回完整证据")
    if not restart_arbiter():
        return
    uid, aid, cid = ctx["uid"], ctx["aid"], ctx["cid"]

    status, body = http_get(f"/api/v1/conclusion/{uid}")
    check(status == 200, f"重启后读取唯一结论 HTTP 200（实际 {status}）")
    expect_unique_evidence(body.get("conclusion", {}), unique_payload(uid),
                           "重启后读取")
    check(body.get("conclusion") == ctx["unique"],
          "重启后唯一结论与首次封存完全一致")
    check(body.get("sealed_at") == ctx["unique_sealed_at"]
          and body.get("request_hash") == ctx["unique_hash"],
          "重启后审计标识的封存时间与请求指纹不变")

    status, body = http_get(f"/api/v1/conclusion/{aid}")
    check(status == 200, f"重启后读取歧义结论 HTTP 200（实际 {status}）")
    expect_ambiguous_evidence(body.get("conclusion", {}), ambiguous_payload(aid),
                              "重启后读取", ctx["ambiguous"]["production_sequences"])
    check(body.get("conclusion") == ctx["ambiguous"],
          "重启后歧义结论与首次封存完全一致（两棵见证树）")

    status, body = http_get(f"/api/v1/conclusion/{cid}")
    check(status == 200 and body.get("conclusion") == ctx["cycle"],
          "重启后拒绝结论保持不变（NONCONSUMING_CYCLE 证据完整）")

    # Equivalent retransmission after the restart replays full evidence.
    status, body = http_post("/api/v1/analyze", shuffled(ambiguous_payload(aid)))
    check(status == 200 and body.get("seal_status") == "REPLAYED",
          f"重启后等价重传回放 REPLAYED（实际 HTTP {status} "
          f"{body.get('seal_status')}）")
    expect_ambiguous_evidence(body.get("result", {}), ambiguous_payload(aid),
                              "重启后等价重传",
                              ctx["ambiguous"]["production_sequences"])
    check(body.get("result") == ctx["ambiguous"],
          "重启后等价重传的证据与首次封存完全一致")

    status, body = http_post("/api/v1/analyze", shuffled(unique_payload(uid)))
    check(status == 200 and body.get("result") == ctx["unique"],
          "重启后唯一文法等价重传返回完整唯一树")

    # Conflict behaviour after restart: original evidence, with trees.
    conflict = unique_payload(uid)
    conflict["tokens"] = ["a"]
    conflict["productions"] = [{"id": 1, "lhs": "S", "rhs": ["a"]}]
    status, body = http_post("/api/v1/analyze", conflict)
    check(status == 409 and body.get("error") == "AUDIT_ID_CONFLICT",
          f"重启后同标识不同输入仍冲突 HTTP 409（实际 {status}）")
    check(body.get("original_evidence", {}).get("conclusion") == ctx["unique"],
          "重启后冲突响应保留的原始证据仍含完整唯一树")


def scenario_legacy(ctx):
    step("步骤 6/6：遗留封存（证据被裁剪）安全恢复并跨重启保持完整")
    lu_payload = {
        "audit_id": ctx["lu"],
        "nonterminals": ["S"],
        "productions": [{"id": 5, "lhs": "S", "rhs": ["x", "y"]}],
        "start": "S",
        "tokens": ["x", "y"],
    }
    la_payload = {
        "audit_id": ctx["la"],
        "nonterminals": ["S"],
        "productions": [{"id": 7, "lhs": "S", "rhs": ["z"]},
                        {"id": 8, "lhs": "S", "rhs": ["z"]}],
        "start": "S",
        "tokens": ["z"],
    }
    lu_entry, lu_full = make_legacy_entry(lu_payload)
    la_entry, la_full = make_legacy_entry(la_payload)
    check(lu_entry["conclusion"].get("archived_tree") is True
          and "tree" not in lu_entry["conclusion"],
          "遗留夹具：唯一结论已被裁剪（archived_tree 标记）")
    check(la_entry["conclusion"].get("archived_witnesses") == ["first", "second"]
          and "trees" not in la_entry["conclusion"],
          "遗留夹具：歧义结论已被裁剪（archived_witnesses 标记）")

    if not seed_store_entries({ctx["lu"]: lu_entry, ctx["la"]: la_entry}):
        return
    if not restart_arbiter():
        return

    # Legacy entries are recovered from their frozen inputs.
    status, body = http_get(f"/api/v1/conclusion/{ctx['lu']}")
    check(status == 200, f"遗留唯一结论读取 HTTP 200（实际 {status}）")
    concl = body.get("conclusion", {})
    expect_unique_evidence(concl, lu_payload, "遗留唯一恢复")
    check(concl == lu_full, "遗留唯一结论恢复为完整可复核证据")
    check("archived_tree" not in concl, "恢复后不再保留 archived_tree 裁剪标记")
    check(body.get("request_hash") == lu_entry["request_hash"]
          and body.get("sealed_at") == LEGACY_SEALED_AT,
          "恢复不改变请求指纹与封存时间")

    status, body = http_get(f"/api/v1/conclusion/{ctx['la']}")
    check(status == 200, f"遗留歧义结论读取 HTTP 200（实际 {status}）")
    concl = body.get("conclusion", {})
    expect_ambiguous_evidence(concl, la_payload, "遗留歧义恢复")
    check(concl == la_full, "遗留歧义结论恢复为两棵完整见证树")
    check("archived_witnesses" not in concl,
          "恢复后不再保留 archived_witnesses 裁剪标记")
    check(body.get("request_hash") == la_entry["request_hash"]
          and body.get("sealed_at") == LEGACY_SEALED_AT,
          "恢复不改变歧义结论的请求指纹与封存时间")

    # Equivalent retransmission of a legacy id replays the recovered evidence.
    status, body = http_post("/api/v1/analyze", shuffled(la_payload))
    check(status == 200 and body.get("seal_status") == "REPLAYED"
          and body.get("result") == la_full,
          f"遗留标识等价重传回放完整证据（实际 HTTP {status} "
          f"{body.get('seal_status')}）")

    # Earlier entries are untouched by the recovery.
    status, body = http_get(f"/api/v1/conclusion/{ctx['aid']}")
    check(status == 200 and body.get("conclusion") == ctx["ambiguous"],
          "恢复后既有歧义结论保持不变")
    status, body = http_get(f"/api/v1/conclusion/{ctx['cid']}")
    check(status == 200 and body.get("conclusion") == ctx["cycle"],
          "恢复后既有拒绝结论保持不变")

    # One more restart: the recovery must have been persisted.
    if not restart_arbiter():
        return
    ok = True
    for audit_id, expect in ((ctx["lu"], lu_full), (ctx["la"], la_full),
                             (ctx["uid"], ctx["unique"]),
                             (ctx["aid"], ctx["ambiguous"]),
                             (ctx["cid"], ctx["cycle"])):
        status, body = http_get(f"/api/v1/conclusion/{audit_id}")
        if not (status == 200 and body.get("conclusion") == expect):
            ok = False
            check(False, f"再次重启后 {audit_id} 的证据不完整（HTTP {status}）")
    check(ok, "再次重启后全部结论（含恢复结果）保持完整可复核")


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
    ctx = {
        "uid": f"verify-unique-{run_id}",
        "aid": f"verify-amb-{run_id}",
        "cid": f"verify-cycle-{run_id}",
        "lu": f"verify-legacy-uni-{run_id}",
        "la": f"verify-legacy-amb-{run_id}",
    }

    ctx["unique"], ctx["unique_sealed_at"], ctx["unique_hash"] = \
        scenario_unique(ctx["uid"])
    check(bool(ctx["unique_sealed_at"]) and bool(ctx["unique_hash"]),
          "首次响应携带封存时间与请求指纹")
    ctx["ambiguous"] = scenario_ambiguous(ctx["aid"], f"verify-amb2-{run_id}")
    ctx["cycle"] = scenario_cycle(ctx["cid"])
    scenario_after_restart(ctx)
    scenario_legacy(ctx)

    return report()


def report() -> int:
    print("\n================ 验收汇总 ================")
    if failures:
        print(f"失败 {len(failures)} 项：")
        for f in failures:
            print(f"  - {f}")
        print("RESULT: FAIL")
        return 1
    print("全部步骤通过：单元测试 / 镜像 / 唯一 / 歧义 / 无消费环 / 回放 / 冲突 "
          "/ 重启证据完整 / 遗留恢复")
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
