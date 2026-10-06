# 深空着陆器文法仲裁服务（Shared Packed Parse Forest Arbiter）

地面规则离线转交的故障处置指令，需要确认一串已捕获词元**不会被两条不同的有限推导解释成不同动作序列**。
本服务对任意上下文无关文法（允许空产生式、直接/间接左递归）在**不枚举全部推导**的前提下，
基于共享打包解析森林（Earley + 二值化 SPPF）给出三态判定：

| verdict | 含义 |
|---|---|
| `REJECTED` | 拒绝：词元不被接受 / 起始符号无法派生 / 存在可达的不消费词元循环 |
| `UNIQUE_ACCEPTED` | 唯一接受，返回唯一派生树 |
| `AMBIGUOUS_ACCEPTED` | 歧义接受，返回按产生式编号序列稳定选出的**两棵不同有限派生树** |

## 协议限制

- 非终结符 ≤ 16；产生式 ≤ 32 且编号唯一（正整数）；输入词元 ≤ 48，均为可打印 ASCII
- 产生式右部可为空数组（ε）；文法可含直接或间接左递归
- 可选字段 `terminals` 给出显式词元字母表；提供后，右部未解析符号按**悬空引用**拒绝

## 判定与证据规则

- **共享森林**：每个打包节点只保留字典序最小的**两个**不同先序产生式编号序列；
  树数以饱和值 `{0,1,2}` 计数，因此 48 个高度歧义词元（解析数可达 Catalan 量级）也在毫秒级完成，绝不枚举推导。
- **稳定选树**：先序产生式编号序列与具体派生树一一对应，构成稳定全序。
  `first` = 字典序最小序列，`second` = 字典序次小序列（即在尽量晚的位置分歧，而非首个可分歧点）。
- **可达不消费词元循环**：静态分析构造有限 ε 可消集 R 与零消费边
  （产生式无终结符，且除目标符号外其余符号都在 R 中），从起始符号可达的有向环一律明确拒绝，
  返回环路径与各步产生式编号——无限展开不会被伪装成证据。
- **首个可操作原因**：非法符号、悬空引用、编号重复、超限等结构问题按检查顺序返回首个原因（中文 `detail`）。

## 审计封存

- 新审计标识：计算并封存结论（`SEALED`），落盘到 `/data/sealed.json`（原子替换）。
- 同标识 + 语义等价重传（与声明/产生式数组顺序无关，仅与内容有关）：回放原结论（`REPLAYED`），不重新计算。
- 同标识 + 不同输入：`HTTP 409 AUDIT_ID_CONFLICT`，**保留并回传原证据**。
- **完整证据跨重启保持**：唯一树 / 两棵歧义见证树作为封存结论的一部分原样落盘；
  保持数据卷不变重启后，按审计标识读取或等价重传仍返回完整派生树、产生式编号序列与跨度。
- **遗留恢复**：旧版本封存的记录可能缺失树证据（留有 `archived_tree` / `archived_witnesses`
  裁剪标记）。服务启动时依据其冻结的规范化输入重算，仅当重算的裁决与产生式编号序列和
  封存残迹完全一致时才采纳恢复结果并落盘；否则原记录保持不动。恢复不改变审计标识、
  请求指纹、封存时间、拒绝结论或冲突时保留的原始证据。

## HTTP

`POST /api/v1/analyze`

```json
{
  "audit_id": "mission-001",
  "nonterminals": ["E"],
  "productions": [
    {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
    {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
    {"id": 3, "lhs": "E", "rhs": ["id"]}
  ],
  "start": "E",
  "tokens": ["id", "+", "id", "*", "id"]
}
```

- `GET /healthz` 健康响应；`GET /api/v1/conclusion/<audit_id>` 取回封存结论
- 端口经环境变量配置：`ARBITER_HOST`（默认 `0.0.0.0`）、`ARBITER_PORT`（默认 `8080`）、
  `ARBITER_STORE`（默认 `/data/sealed.json`）
- 纯 Python 标准库实现，无运行时第三方依赖

## Compose 验收

验收以名为 `verify` 的服务**一次执行后退出并返回状态码**（全通过 0，任一失败 1）。
推荐用 `run`，其退出码即验收状态码：

```bash
# 自动先构建镜像、等待 arbiter 健康，再在 verify 内执行：
# 单元测试 -> 显式镜像构建 -> 唯一/歧义/无消费环（含回放、冲突）HTTP 冒烟
# -> 保留数据卷重启 arbiter 后校验读取与等价重传的完整树证据
# -> 注入遗留裁剪封存、再两次重启确认安全恢复且恢复结果持久化
docker compose run --rm --build verify
echo "verify 退出码：$?"
```

或整组启动（较新 Compose 可在 verify 失败时一并中止）：

```bash
ARBITER_HOST_PORT=9090 docker compose up --build --abort-on-container-failure verify
docker compose down -v   # 清理
```

宿主端口经 `ARBITER_HOST_PORT` 配置（默认映射 `8080:8080`）。

## 本地开发与测试

```bash
python3 -m unittest discover -s tests -v       # 52 项单元测试
python3 -m app.service                          # 直接启动服务
ALLOW_LOCAL_FALLBACK=1 bash scripts/entrypoint.sh  # 无 Docker 时本地完整验收
```

## 目录

```
app/grammar.py    请求结构校验（限制/非法符号/悬空引用/首个原因）
app/engine.py     静态分析（可生成性、不消费词元循环）+ Earley/SPPF 构建 + 稳定选树
app/storage.py    语义指纹、封存、回放、冲突保留、完整证据持久化与遗留恢复
app/service.py    HTTP 服务
tests/            引擎/封存/HTTP 单元测试
scripts/          verify.py（冒烟）与 entrypoint.sh（验收编排）
Dockerfile        仲裁服务镜像
Dockerfile.verify 验收镜像（Python + 静态 docker CLI）
docker-compose.yml
```
