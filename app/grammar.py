"""Grammar definition and first-stage validation.

A submission consists of:

* a stable audit identifier,
* at most 16 nonterminals,
* at most 32 uniquely numbered productions (empty right-hand sides and
  direct/indirect left recursion are allowed),
* an input stream of at most 48 printable ASCII tokens.

Every symbol on a right-hand side that is not a declared nonterminal is
treated as a terminal and matched literally against the input tokens.

Validation here only checks the *shape* of the request.  Properties that
require analysis of the grammar or of the parse (non-consuming cycles,
whether the start symbol can derive the input) live in :mod:`app.engine`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# Hard protocol limits.
MAX_NONTERMINALS = 16
MAX_PRODUCTIONS = 32
MAX_TOKENS = 48


class ValidationError(Exception):
    """A structural problem with a submitted grammar.

    ``reason`` is a short stable code, ``detail`` is a human-readable,
    actionable Chinese explanation: the first actionable reason for
    rejection.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Production:
    """A numbered production ``lhs -> rhs``."""

    id: int
    lhs: str
    rhs: tuple  # tuple[str, ...]


@dataclass
class Grammar:
    start: str
    nonterminals: List[str]
    productions: List[Production]
    tokens: List[str]
    by_lhs: dict = field(default_factory=dict, repr=False)
    by_id: dict = field(default_factory=dict, repr=False)
    is_nt: dict = field(default_factory=dict, repr=False)

    def productions_of(self, nt: str) -> List[Production]:
        return self.by_lhs.get(nt, [])


def _is_ascii_token(name: str) -> bool:
    return bool(name) and all(0x20 <= ord(ch) <= 0x7E for ch in name)


def _validate_name(name, kind: str) -> str:
    if not isinstance(name, str):
        raise ValidationError("INVALID_SYMBOL", f"{kind}必须为字符串")
    if not name:
        raise ValidationError("INVALID_SYMBOL", f"{kind}不得为空字符串")
    if not _is_ascii_token(name):
        raise ValidationError(
            "INVALID_SYMBOL",
            f"{kind} {name!r} 含非可打印 ASCII 字符（每个字符须位于 0x20-0x7E）",
        )
    return name


def build_grammar(payload: dict) -> Grammar:
    """Validate the request envelope and construct a :class:`Grammar`.

    Raises :class:`ValidationError` for the first actionable problem.
    """
    if not isinstance(payload, dict):
        raise ValidationError("INVALID_REQUEST", "请求体必须为 JSON 对象")

    nt_field = payload.get("nonterminals")
    prod_field = payload.get("productions")
    start = payload.get("start")
    tokens = payload.get("tokens", [])
    terminals_field = payload.get("terminals")

    # --- nonterminals ---
    if not isinstance(nt_field, list):
        raise ValidationError("INVALID_NONTERMINALS", "字段 nonterminals 必须为数组")
    if len(nt_field) == 0:
        raise ValidationError("INVALID_NONTERMINALS", "至少需要一个非终结符")
    if len(nt_field) > MAX_NONTERMINALS:
        raise ValidationError(
            "LIMIT_EXCEEDED", f"非终结符数量 {len(nt_field)} 超过上限 {MAX_NONTERMINALS}"
        )
    nonterminals: List[str] = []
    seen: set = set()
    for raw in nt_field:
        name = _validate_name(raw, "非终结符")
        if name in seen:
            raise ValidationError("DUP_NONTERMINAL", f"非终结符 {name!r} 重复声明")
        seen.add(name)
        nonterminals.append(name)
    is_nt = {n: True for n in nonterminals}

    # --- start symbol ---
    start = _validate_name(start, "起始符号")
    if start not in seen:
        raise ValidationError(
            "DANGLING_NONTERMINAL",
            f"起始符号 {start!r} 悬空：未在 nonterminals 中声明",
        )

    # --- optional explicit terminal alphabet ---------------------------
    # When supplied, every RHS symbol must resolve to either a declared
    # nonterminal or a member of this alphabet; an unresolved reference is
    # a dangling reference.  When omitted, every non-NT RHS symbol is an
    # implicit literal terminal.
    declared_terminals: set = set()
    if terminals_field is not None:
        if not isinstance(terminals_field, list):
            raise ValidationError("INVALID_TERMINALS", "字段 terminals 必须为数组")
        if len(terminals_field) > MAX_TOKENS:
            raise ValidationError(
                "LIMIT_EXCEEDED", f"词元种类数 {len(terminals_field)} 超过上限 {MAX_TOKENS}"
            )
        for idx, raw in enumerate(terminals_field):
            t = _validate_name(raw, f"第 {idx + 1} 个词元种类")
            if t in is_nt:
                raise ValidationError(
                    "INVALID_SYMBOL", f"词元 {t!r} 与非终结符同名，两个名字空间不得重叠"
                )
            if t in declared_terminals:
                raise ValidationError("DUP_TERMINAL", f"词元种类 {t!r} 重复声明")
            declared_terminals.add(t)

    # --- input token stream ---
    if not isinstance(tokens, list):
        raise ValidationError("INVALID_TOKENS", "字段 tokens 必须为数组（待判定的输入词元序列）")
    if len(tokens) > MAX_TOKENS:
        raise ValidationError(
            "LIMIT_EXCEEDED", f"输入词元数 {len(tokens)} 超过上限 {MAX_TOKENS}"
        )
    input_tokens: List[str] = []
    for idx, raw in enumerate(tokens):
        t = _validate_name(raw, f"第 {idx + 1} 个输入词元")
        if t in is_nt:
            raise ValidationError(
                "INVALID_SYMBOL", f"输入词元 {t!r} 与已声明非终结符同名，词元与非终结符名字空间不得重叠"
            )
        if declared_terminals and t not in declared_terminals:
            raise ValidationError(
                "TOKEN_NOT_IN_ALPHABET",
                f"第 {idx + 1} 个输入词元 {t!r} 不在已声明的 terminals 字母表 {sorted(declared_terminals)} 中",
            )
        input_tokens.append(t)

    # --- productions ---
    if not isinstance(prod_field, list):
        raise ValidationError("INVALID_PRODUCTIONS", "字段 productions 必须为数组")
    if len(prod_field) == 0:
        raise ValidationError("NO_PRODUCTIONS", "至少需要一条产生式")
    if len(prod_field) > MAX_PRODUCTIONS:
        raise ValidationError(
            "LIMIT_EXCEEDED", f"产生式数量 {len(prod_field)} 超过上限 {MAX_PRODUCTIONS}"
        )

    productions: List[Production] = []
    used_ids: set = set()
    terminals: set = set()

    for idx, raw in enumerate(prod_field):
        where = f"第 {idx + 1} 条产生式"
        if not isinstance(raw, dict):
            raise ValidationError("INVALID_PRODUCTION", f"{where}必须为对象")
        pid = raw.get("id")
        lhs = raw.get("lhs")
        rhs = raw.get("rhs")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
            raise ValidationError("INVALID_PRODUCTION_ID", f"{where}的 id 必须为正整数")
        if pid in used_ids:
            raise ValidationError("DUP_PRODUCTION_ID", f"产生式编号 {pid} 重复")
        used_ids.add(pid)

        lhs = _validate_name(lhs, f"{where}的左部")
        if lhs not in is_nt:
            raise ValidationError(
                "DANGLING_NONTERMINAL",
                f"{where}左部 {lhs!r} 悬空：未在 nonterminals 中声明（左部只能是非终结符）",
            )
        if not isinstance(rhs, list):
            raise ValidationError("INVALID_RHS", f"{where}的右部必须为数组（空数组表示 ε）")
        rhs_names: List[str] = []
        for sym in rhs:
            s = _validate_name(sym, f"{where}右部符号")
            if s not in is_nt:
                if declared_terminals and s not in declared_terminals:
                    raise ValidationError(
                        "DANGLING_SYMBOL",
                        f"{where}右部符号 {s!r} 悬空：既不是已声明非终结符，也不在 terminals 字母表中",
                    )
                terminals.add(s)
            rhs_names.append(s)
        productions.append(Production(id=pid, lhs=lhs, rhs=tuple(rhs_names)))

    if len(terminals) > MAX_TOKENS:
        raise ValidationError(
            "LIMIT_EXCEEDED", f"右部出现的不同词元种类 {len(terminals)} 超过上限 {MAX_TOKENS}"
        )

    # All later algorithms iterate production ids in numeric order; the
    # submission order of the array is irrelevant.
    productions.sort(key=lambda p: p.id)
    by_lhs: dict = {}
    for p in productions:
        by_lhs.setdefault(p.lhs, []).append(p)
    by_id = {p.id: p for p in productions}

    return Grammar(
        start=start,
        nonterminals=nonterminals,
        productions=productions,
        tokens=input_tokens,
        by_lhs=by_lhs,
        by_id=by_id,
        is_nt=is_nt,
    )
