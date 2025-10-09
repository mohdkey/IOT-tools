# LLM File-Input Audit

> 用 **LLM（大语言模型：能理解/生成自然语言的模型）** 自动判定固件二进制是否**可通过文件或路径参数进行输入**，并给出 **AFL++（模糊测试框架：向程序注入变异数据以触发异常）** 的启动建议。脚本支持**交互式运行**、**自动扫描生成二进制清单**、**网络预检**、**重试与退避（exponential backoff：逐次拉长重试间隔）**、**离线启发式（heuristic：基于经验规则的推断）降级**、以及生成 **HTML 报告**与**详细日志**。

---

## ✨ 功能特性

- **自动收集目标程序**：不存在 `binaries.txt` 时，引导扫描固件根目录（默认 `./squashfs-root`），只选 **ELF（可执行与可链接格式）** 或具有执行位的文件，并默认跳过 `.so`。
- **多轮帮助探测**：依次尝试 `(无)、-h、--help、-help、-?、/?, help` 收集 `Usage` 文本。
- **LLM 批处理分析**：每 10 个程序一批；对 **429/5xx/超时** 自动**重试两次**（总 3 次）。
- **判定维度**：  
  - `accepts_input`：是否接受**路径型输入**（文件内容或资源路径）。  
  - `input_kind`：`content_file`（读取/解析文件内容）或 `path_resource`（FILESYSTEM/DEVICE/MOUNTPOINT/DIR 等**资源类路径**）。  
  - `stdin_supported`：是否支持 **STDIN（标准输入：程序默认输入流）**。  
- **AFL++ 启动建议**：根据 `input_kind` 自动给出 `@@`/stdin/argv 包装器建议。
- **离线启发式降级**：LLM 不可用时，仍可基于规则产出可靠结果。
- **输出三件套**：`llm_audit.json`、`llm_audit.csv`、**`llm_audit.html`（可搜索、彩色徽标）**。
- **日志**：终端**信息级**；文件 `llm_audit.log` **调试级**（每次运行清空）。
- **网络预检（preflight：正式调用前的连通性/鉴权测试）**：支持 **代理（proxy：中转 HTTP 请求的服务器）** 与 **TLS（传输层安全协议：用于加密通信）** 校验开关。

> 本 README 对应脚本：`llm_file_input_audit.py`（见仓库）。

---

## 🧰 依赖

- Python 3.8+
- `requests`（HTTP 客户端库）
- （可选）AFL++、QEMU 静态解释器（如 `qemu-arm-static`）
- 具有调用权限的 **OpenAI API Key（应用程序编程接口密钥：用于鉴权）**

---

## 🚀 快速开始

```bash
sudo python3 llm_file_input_audit.py
```

按提示输入：

1. `OPENAI_API_KEY`（可提前写入脚本中的 `HARDCODED_API_KEY`，或用环境变量）  
2. 二进制列表文件路径（默认 `binaries.txt`；不存在将引导**自动扫描生成**）  
3. QEMU 前缀（默认 `qemu-arm-static -L ./squashfs-root`）与额外环境变量（例如 `QEMU_LD_PREFIX=./squashfs-root`）  
4. 每个帮助调用超时（默认 2s）  
5. 输出文件名（JSON/CSV；HTML 会自动伴生）  
6. 代理与 TLS 校验设置（可选）

运行结束后查看：

- `llm_audit.json`、`llm_audit.csv`、**`llm_audit.html`**
- 日志：`llm_audit.log`

---

## 🧭 判定标准（更贴近“可模糊测试”）

- **content_file**：帮助文本出现“读取/加载/解析 FILE”的迹象，如 `-f FILE`、`--file FILE`、`--input FILE`、`[FILE]...` 或“无文件则读标准输入”。  
- **path_resource**：如 `df [FILESYSTEM]`、`findmnt <device>|<mountpoint>`，虽然不读文件**内容**，但其**路径型参数**可驱动程序逻辑，适合通过 **argv（命令行参数：程序启动时接收的参数列表）** 模糊测试。  
- **非输入**：如 `fsync FILE`（只对描述符刷盘，不读取内容），若帮助文本未说明读取内容，则记为 `false/unknown`。

> 比喻：`content_file` 像“让程序读一封信的内容”；`path_resource` 像“告诉程序去哪个房间”，不看信纸但会改变程序行为。

---

## 🧪 AFL++ 启动建议

- **content_file**（读取文件内容）：
  ```bash
  afl-fuzz -i input -o output -- /path/to/bin --input @@
  # 或
  afl-fuzz -i input -o output -- /path/to/bin @@
  ```
- **path_resource**（路径/设备/挂载点等资源类）：
  ```bash
  # 将 @@ 的内容作为“命令行参数字符串”传入（argv 包装器）
  afl-fuzz -i input -o output -- /bin/sh -lc '/path/to/bin "$(cat @@)"'
  ```
- **仅支持 STDIN**：
  ```bash
  afl-fuzz -i input -o output -- /path/to/bin < @@
  ```

脚本会在结果中生成 `suggested_afl_cmd` 字段作为“起步命令”。

---

## ⚙️ 交互项说明

- **API Key**：支持脚本内硬编码或环境变量 `OPENAI_API_KEY`。  
- **列表生成**：若 `binaries.txt` 不存在，脚本会扫描 `./squashfs-root`（可改），仅采 **ELF** 或具执行位文件，并默认忽略 `.so`。  
- **QEMU 前缀**：用于跨架构运行目标二进制（例如 ARM 固件在 x86 主机上执行）。  
- **代理/TLS**：可指定 HTTP(S) 代理；若存在内网 TLS 拦截，可临时关闭校验（仅限调试）。

---

## 📤 输出格式

- **JSON**：
  ```json
  {
    "count": 123,
    "results": [
      {
        "program": "/path/to/bin",
        "accepts_input": true,
        "input_kind": "path_resource",
        "input_flags": ["FILESYSTEM"],
        "stdin_supported": "false",
        "suggested_afl_cmd": "/path/to/bin <ARG> ...",
        "notes": "quoted from help",
        "help_args_used": "-h"
      }
    ]
  }
  ```

- **CSV**：列为  
  `program,input_kind,accepts_input,input_flags,stdin_supported,suggested_afl_cmd,notes,help_args_used`

- **HTML**：`llm_audit.html`，带搜索框与彩色徽标，便于快速筛选。

---

## 🌐 网络与鉴权

- **预检**：启动前对 `chat/completions` 做一次轻量请求，快速检测 **代理（ProxyError）**、**证书（SSLError）**、**连接（ConnectionError）** 与 **401（未授权）**。  
- **重试**：对 429/5xx/超时采用**退避**策略自动重试。  
- **降级**：LLM 仍失败 ⇒ 自动切换**启发式**解析，保证流程不中断。

---

## 🪵 日志

- 终端：**信息级（Info）**，关键动作可见；  
- 文件：`llm_audit.log` **调试级（Debug）**，包含帮助原文片段、请求与响应摘要、重试细节；  
- 每次运行会清空旧日志，防止混淆。

---

## ❓FAQ

**Q1：为什么 `df [FILESYSTEM]` 和 `findmnt <device>|<mountpoint>` 会被判定为可模糊测试？**  
因为它们的**路径型参数**会显著影响程序分支与遍历，适合通过 **argv** 进行模糊测试，虽然不读取文件**内容**，但依然有价值。

**Q2：遇到 429 怎么办？**  
脚本已内置重试与退避；同时建议合批请求、控制输入长度，并在平台控制台按需申请提升 **rate limit（速率限制：单位时间内请求/令牌上限）**。


---

