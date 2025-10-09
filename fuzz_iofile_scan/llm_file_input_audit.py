#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_file_input_audit.py
- 交互式参数输入，自动扫描/生成 binaries.txt
- 终端日志：详细；文件日志 llm_audit.log：调试（每次运行清空）
- 常见帮助参数：(无)、-h、--help、-help、-?、/?, help
- 每 10 个一组调用 LLM；失败(429/5xx/超时)自动重试(总3次)；仍失败则启用本地启发式降级
- 支持代理/忽略TLS；启动前做预检（连通性/鉴权）
- 输出：JSON/CSV + HTML 报告
"""

import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' package is required. Try: pip install requests", file=sys.stderr)
    sys.exit(2)

# ===== 固定大模型配置（可用环境变量覆盖） =====
DEFAULT_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
HARDCODED_API_KEY = ""  # 可直接填入你的 API Key；留空则询问/使用 OPENAI_API_KEY 环境变量

HELP_TRIES = [
    [], ["-h"], ["--help"], ["-help"], ["-?"], ["/?"], ["help"],
]

# HTTP client options (在 main() 中赋值)
GLOBAL_REQUESTS_PROXIES = None  # e.g., {'http': 'http://...', 'https': 'http://...'}
GLOBAL_VERIFY_SSL = True

# ---------------- Logging ----------------
class Logger:
    def __init__(self, path: str = "llm_audit.log", overwrite: bool = True):
        self.path = path
        self.fp = open(self.path, "w" if overwrite else "a", encoding="utf-8")
    def _stamp(self) -> str:
        return time.strftime("[%Y-%m-%d %H:%M:%S]")
    def info(self, msg: str):
        line = f"{self._stamp()} {msg}"
        print(line)
        self.fp.write(line + "\n"); self.fp.flush()
    def debug(self, msg: str):
        line = f"{self._stamp()} {msg}"
        self.fp.write(line + "\n"); self.fp.flush()
    def close(self):
        try: self.fp.close()
        except Exception: pass

logger = Logger("llm_audit.log", overwrite=True)

# --------- 实用函数 ----------
def interactive_input(prompt: str, default: Optional[str] = None) -> str:
    tip = f" [{default}]" if default not in (None, "") else ""
    s = input(f"{prompt}{tip}: ").strip()
    if s == "" and default is not None:
        return default
    return s

def is_exec_bit(path: str) -> bool:
    try:
        st = os.stat(path)
        return os.path.isfile(path) and (st.st_mode & 0o111) != 0
    except Exception:
        return False

def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def should_skip_shared_object(path: str) -> bool:
    p = path.lower()
    if ".so" in os.path.basename(p) or "/lib/" in p or "/lib64/" in p:
        return True
    return False

def scan_binaries(root: str, elf_only: bool = True, skip_so: bool = True, common_dirs_only: bool = False, max_count: int = 0) -> List[str]:
    root = os.path.abspath(root)
    candidates: List[str] = []
    if common_dirs_only:
        dirs = ["bin","sbin","usr/bin","usr/sbin"]
        search_dirs = [os.path.join(root, d) for d in dirs]
    else:
        search_dirs = [root]

    for base in search_dirs:
        for dirpath, dirnames, filenames in os.walk(base):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    if skip_so and should_skip_shared_object(p):
                        continue
                    if elf_only:
                        if is_elf(p):
                            candidates.append(p)
                    else:
                        if is_exec_bit(p):
                            candidates.append(p)
                except Exception:
                    continue
                if max_count and len(candidates) >= max_count:
                    uniq = sorted(set(candidates))
                    logger.info(f"[SCAN] 达到上限 {max_count}，提前结束。当前计数={len(uniq)}")
                    return uniq
    uniq = sorted(set(candidates))
    logger.info(f"[SCAN] 完成。候选={len(uniq)}")
    return uniq

def write_list_file(paths: List[str], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        for p in paths:
            f.write(p + "\n")
    logger.info(f"[LIST] 已写出清单：{out_path}（{len(paths)} 项）")

def build_command(prefix: Optional[str], exe: str) -> List[str]:
    parts: List[str] = []
    if prefix:
        parts.extend(shlex.split(prefix))
    parts.append(exe)
    return parts

def run_help(cmd: List[str], env: Dict[str,str], timeout: float) -> Tuple[str, int, str]:
    combined, rc, used = "", 0, ""
    for args in HELP_TRIES:
        try_args = cmd + args
        try:
            cp = subprocess.run(
                try_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env or None, timeout=timeout, text=True, errors="replace"
            )
            out = (cp.stdout or "") + "\n" + (cp.stderr or "")
            combined += f"\n--- TRY {' '.join(args) or '(no-args)'} ---\n{out}\n"
            rc = cp.returncode
            used = " ".join(args) if args else ""
            short = out.strip().splitlines()[:4]
            preview = (" | ".join(short))[:300]
            logger.info(f"[HELP] cmd={' '.join(try_args)} | rc={rc} | used={used or '(no-args)'} | preview={preview}")
            logger.debug(f"[HELP-RAW] for {' '.join(try_args)}\n{out}\n")
            if re.search(r"\bUsage\b|\busage\b|--help|-h|-help|/\?", out):
                break
        except subprocess.TimeoutExpired:
            combined += "\n[TIMEOUT]\n"
            used = "timeout"
            logger.info(f"[HELP] 超时：{' '.join(try_args)}")
        except Exception as e:
            combined += f"\n[ERROR] {e}\n"
            used = "error"
            logger.info(f"[HELP] 错误：{' '.join(try_args)} => {e}")
    return combined, rc, used

def extract_json_block(text: str) -> Optional[str]:
    m = re.search(r"(\[\s*\{.*\}\s*\])", text, flags=re.S)
    if m: return m.group(1)
    m = re.search(r"(\{.*\})", text, flags=re.S)
    if m: return f"[{m.group(1)}]"
    return None

def chunked(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i+size]

def preflight_check(api_key: str, base_url: str, model: str) -> bool:
    """Quick connectivity check. Returns True if minimal call works, else False."""
    test_url = base_url.rstrip('/') + '/chat/completions'
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type':'application/json'}
    payload = {'model': model, 'messages':[{'role':'user','content':'ping'}], 'temperature':0}
    try:
        resp = requests.post(test_url, headers=headers, json=payload, timeout=10, proxies=GLOBAL_REQUESTS_PROXIES, verify=GLOBAL_VERIFY_SSL)
        logger.info(f"[PREFLIGHT] HTTP {resp.status_code} -> {test_url}")
        if resp.status_code == 401:
            logger.info('[PREFLIGHT] 认证失败：请检查 API Key/项目权限。')
        return resp.ok
    except requests.exceptions.SSLError as e:
        logger.info(f"[PREFLIGHT] TLS 证书错误：{e}")
    except requests.exceptions.ProxyError as e:
        logger.info(f"[PREFLIGHT] 代理错误：{e}")
    except requests.exceptions.ConnectionError as e:
        logger.info(f"[PREFLIGHT] 网络连接失败：{e}")
    except Exception as e:
        logger.info(f"[PREFLIGHT] 失败：{e}")
    return False

def call_openai_chat(api_key: str, base_url: str, model: str, messages: List[Dict], timeout: float = 60.0) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": messages, "temperature": 0.2}
    attempts = 3
    backoffs = [1.5, 3.0]
    last_err = None
    for attempt in range(1, attempts + 1):
        logger.info(f"[LLM] 调用开始 -> {url} | model={model} | attempt={attempt}/{attempts}")
        try:
            logger.debug(f"[LLM-REQ] headers={{'Content-Type':'application/json','Authorization':'Bearer ****'}} payload={json.dumps(payload)[:2000]}")
        except Exception:
            pass
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout, proxies=GLOBAL_REQUESTS_PROXIES, verify=GLOBAL_VERIFY_SSL)
            logger.info(f"[LLM] HTTP {resp.status_code}")
            if resp.status_code in (429, 500, 502, 503, 504):
                if attempt < attempts:
                    wait_s = backoffs[attempt - 1] if attempt - 1 < len(backoffs) else backoffs[-1]
                    logger.info(f"[WARN] LLM 请求失败（status={resp.status_code}），准备重试，等待 {wait_s}s")
                    time.sleep(wait_s)
                    continue
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            logger.debug(f"[LLM-RAW] {json.dumps(data)[:8000]}")
            return content
        except requests.exceptions.RequestException as e:
            last_err = e
            if attempt < attempts:
                wait_s = backoffs[attempt - 1] if attempt - 1 < len(backoffs) else backoffs[-1]
                logger.info(f"[WARN] LLM 请求异常：{e}; 准备重试，等待 {wait_s}s")
                time.sleep(wait_s)
                continue
            logger.info(f"[ERROR] LLM 最终失败：{e}")
            raise

def heuristic_analyze(group_items: List[Dict]) -> List[Dict]:
    """Offline fallback using regex-based heuristics."""
    out = []
    for it in group_items:
        help_s = it.get('help','')
        prog = it.get('program','')
        text = help_s.lower()
        has_content = any(p in text for p in [
            '-f file', '--file', '--input', '--config', 'read from file', 'input file', 'pattern file', 'load from file', '[file]'])
        has_stdin = ('read standard input' in text) or ('read from stdin' in text) or ("'-' for stdin" in text) or ('if no file' in text)
        pr_tokens = ['filesystem','device','mountpoint','dir','directory','interface']
        has_path_res = any(t in text for t in pr_tokens)
        is_fsync = 'fsync' in prog or 'fsync' in text
        accepts_input = 'unknown'
        input_kind = 'unknown'
        input_flags: List[str] = []
        if has_content:
            accepts_input = True
            input_kind = 'content_file'
            if '-f ' in help_s: input_flags.append('-f FILE')
            if ' --file' in help_s or '--file' in text: input_flags.append('--file FILE')
            if ' --input' in help_s or '--input' in text: input_flags.append('--input FILE')
            if '[FILE]' in help_s or ' [file]' in text or ' file]' in text: input_flags.append('FILE')
        elif has_path_res and not is_fsync:
            accepts_input = True
            input_kind = 'path_resource'
            for token in ['FILESYSTEM','<device>','<mountpoint>','DEVICE','MOUNTPOINT','DIR','DIRECTORY','INTERFACE']:
                if token.lower() in text: input_flags.append(token)
        elif is_fsync:
            accepts_input = False
            input_kind = 'unknown'
        stdin_supported = True if has_stdin else 'unknown'
        notes = 'heuristic fallback'
        out.append({
            'program': prog,
            'accepts_input': accepts_input,
            'input_kind': input_kind,
            'input_flags': input_flags,
            'stdin_supported': stdin_supported,
            'notes': notes,
        })
    return out

def suggest_afl(bin_path: str, analysis: Dict) -> str:
    flags = analysis.get("input_flags") or []
    accepts = analysis.get("accepts_input", analysis.get("accepts_file_input"))
    kind = analysis.get("input_kind", "unknown")
    if accepts is True or str(accepts).lower() == "true":
        if kind == "content_file":
            for pref in ["--input","--file","--filename","--source","--conf","--config","-f","-i","FILE"]:
                if pref in flags:
                    if pref == "FILE":
                        return f"{shlex.quote(bin_path)} @@"
                    return f"{shlex.quote(bin_path)} {pref} @@"
            if flags:
                return f"{shlex.quote(bin_path)} {flags[0]} @@"
        if kind == "path_resource":
            example = '# afl-fuzz ... -- /bin/sh -lc "{bin} \\"$(cat @@)\\""'.format(bin=shlex.quote(bin_path))
            return "{bin} <ARG>\n# 建议：使用 wrapper 将 @@ 文件内容作为参数字符串传入，例如：\n{ex}".format(
                bin=shlex.quote(bin_path), ex=example
            )
    if str(analysis.get("stdin_supported")).lower() == "true":
        return f"{shlex.quote(bin_path)} < @@"
    return f"{shlex.quote(bin_path)}  # 无可直接使用的输入；建议编写 harness/argv 包装器"

# ---- LLM 系统提示（定义 content_file vs path_resource） ----
LLM_SYS_PROMPT = """You are a careful security tooling assistant.

TASK
Given up to 10 programs with their HELP/USAGE text, produce EXACTLY ONE JSON object per program (in the SAME ORDER as input).

FIELDS (required)
- program: exact path from input.
- accepts_input: [true|false|"unknown"]  # true if the program accepts ANY path-like input via CLI for processing: either a CONTENT FILE (read/parse) or a PATH RESOURCE (FILESYSTEM/DEVICE/MOUNTPOINT/DIR).
- input_kind: one of ["content_file","path_resource","unknown"]
- input_flags: list of flags/placeholders that denote the input (e.g., ["--input FILE","-f FILE","FILE","FILESYSTEM","<device>","<mountpoint>"]).
- stdin_supported: [true|false|"unknown"]
- notes: 1 short reason, only quoting from the provided help text.

DEFINITIONS
- content_file: program reads/parses file CONTENT (e.g., config, pattern, data, input file). Examples: "read from FILE", "load from FILE", "-f FILE", "[FILE]..." with wording that implies reading content; "if no FILE read standard input".
- path_resource: program uses a PATH-like argument that is NOT read for content but still influences behavior (e.g., FILESYSTEM, DEVICE, MOUNTPOINT, DIR/DIRECTORY). These are considered FUZZABLE via argv strings, even if not content.
- NOT input: flags that only operate on descriptors without parsing content (e.g., fsync FILE), unless help implies reading.
- stdin_supported: true only if help explicitly indicates reading from standard input (e.g., "if no FILE read standard input", "use '-' for stdin").

FORMAT
- STRICT JSON array only, no markdown, no code fences.
- Keep SAME program order.
- If unclear, use "unknown" and explain briefly in notes.
- Do NOT invent flags; prefer exact flags/words from the help text.

EXAMPLES
1) df: "Usage: df ... [FILESYSTEM]..."  => accepts_input=true; input_kind="path_resource"; input_flags includes "FILESYSTEM"; stdin_supported=false.
2) findmnt: "Usage: findmnt [options] <device>|<mountpoint>" => accepts_input=true; input_kind="path_resource"; input_flags includes "<device>","<mountpoint>".
3) fsync: "Usage: fsync FILE..." => accepts_input=false (operates on descriptor; does NOT read content) unless help text states it reads from FILE.
4) grep: "[-f FILE] ... [FILE]..." and "if no FILE read standard input" => accepts_input=true; input_kind="content_file"; input_flags includes "-f FILE","FILE"; stdin_supported=true.
5) echo: no input flags; stdin_supported only if explicitly stated by help; otherwise "unknown".
"""

def write_html_report(results: List[Dict], out_html: str):
    import html
    def esc(s):
        if s is None: return ""
        if isinstance(s, list): return ", ".join(map(str, s))
        return html.escape(str(s))

    summary_total = len(results)
    summary_true_content = sum(1 for r in results if (str(r.get("accepts_input")).lower()=="true" and r.get("input_kind")=="content_file"))
    summary_true_path = sum(1 for r in results if (str(r.get("accepts_input")).lower()=="true" and r.get("input_kind")=="path_resource"))
    summary_unknown = sum(1 for r in results if str(r.get("accepts_input")).lower()=="unknown")

    rows = []
    for r in results:
        badge_kind = r.get("input_kind","unknown")
        color = "#2e7d32" if badge_kind=="content_file" else ("#1565c0" if badge_kind=="path_resource" else "#757575")
        accepts = str(r.get("accepts_input"))
        accepts_color = "#1b5e20" if accepts.lower()=="true" else ("#b71c1c" if accepts.lower()=="false" else "#616161")
        accepts_badge = f'<span style="padding:2px 6px;border-radius:8px;background:{accepts_color};color:white;font-size:12px;">{esc(accepts)}</span>'
        stdin_val = str(r.get("stdin_supported"))
        stdin_color = "#1b5e20" if stdin_val.lower()=="true" else ("#b71c1c" if stdin_val.lower()=="false" else "#616161")
        stdin_badge = f'<span style="padding:2px 6px;border-radius:8px;background:{stdin_color};color:white;font-size:12px;">{esc(r.get("stdin_supported"))}</span>'
        rows.append(f"""
        <tr>
          <td>{esc(r.get("program"))}</td>
          <td><span style="padding:2px 6px;border-radius:8px;background:{color};color:white;font-size:12px;">{esc(badge_kind)}</span></td>
          <td>{accepts_badge}</td>
          <td>{esc(r.get("input_flags"))}</td>
          <td>{stdin_badge}</td>
          <td><code>{esc(r.get("suggested_afl_cmd"))}</code></td>
          <td>{esc(r.get("notes"))}</td>
        </tr>
        """)

    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>LLM Fuzzability Report</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Noto Sans", "PingFang SC", "Microsoft Yahei", sans-serif; margin: 24px; background:#fafafa; }}
h1 {{ margin-bottom: 6px; }}
.summary {{ margin: 12px 0 20px; }}
.table-wrap {{ background:white; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,.06); padding: 12px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
th, td {{ text-align: left; border-bottom: 1px solid #eee; padding: 8px; vertical-align: top; }}
th {{ background: #f7f7f7; position: sticky; top: 0; }}
input[type="search"] {{ width: 320px; padding: 6px 10px; border-radius: 6px; border: 1px solid #ddd; }}
.small {{ color:#666; font-size:13px; }}
</style>
<script>
function filterRows() {{
  const q = document.getElementById('q').value.toLowerCase();
  const rows = document.querySelectorAll('tbody tr');
  rows.forEach(tr => {{
    const txt = tr.innerText.toLowerCase();
    tr.style.display = txt.includes(q) ? '' : 'none';
  }});
}}
</script>
</head>
<body>
  <h1>LLM Fuzzability Report</h1>
  <div class="summary">
    <div>总计：{summary_total}；content_file：{summary_true_content}；path_resource：{summary_true_path}；unknown：{summary_unknown}</div>
    <div class="small">提示：content_file（读取文件内容）；path_resource（路径/设备/挂载点等资源类参数，可通过参数字符串进行模糊测试）。</div>
  </div>
  <div style="margin:8px 0 14px;">
    <input id="q" type="search" placeholder="搜索 program / flags / notes..." oninput="filterRows()"/>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>program</th>
          <th>input_kind</th>
          <th>accepts_input</th>
          <th>input_flags</th>
          <th>stdin_supported</th>
          <th>suggested_afl_cmd</th>
          <th>notes</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
</body>
</html>"""
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_doc)

def main():
    logger.info("[INIT] 启动 LLM File-Input Audit（终端=详细，文件=调试）")
    # API Key 处理
    api_key = (HARDCODED_API_KEY or os.getenv("OPENAI_API_KEY","")).strip()
    if not api_key:
        api_key = input("请输入 OPENAI_API_KEY（留空取消）: ").strip()
        if not api_key:
            logger.info("[ABORT] 未提供 API Key。")
            logger.close(); return 2
    base_url = DEFAULT_BASE_URL
    model = DEFAULT_MODEL
    logger.info(f"[CFG] model={model} base_url={base_url} log_file={logger.path}")

    # 输入列表文件 + 自动扫描
    list_path = input("二进制列表文件路径 [binaries.txt]: ").strip() or "binaries.txt"
    if os.path.exists(list_path):
        try:
            with open(list_path, "r", encoding="utf-8") as _f:
                existing_lines = [ln for ln in _f if ln.strip() and not ln.strip().startswith("#")]
            logger.info(f"[LIST] 检测到已存在的清单：{list_path}（当前 {len(existing_lines)} 项）")
        except Exception:
            logger.info(f"[LIST] 检测到已存在的清单：{list_path}")
        choose = input("是否要重建/覆盖该清单？(y/N): ").strip().lower()
        if choose == "y":
            root = input("固件根目录 [./squashfs-root]: ").strip() or "./squashfs-root"
            elf_only = (input("仅匹配 ELF 文件? [Y/n]: ").strip().lower() or "y") != "n"
            skip_so = (input("跳过共享库(.so)? [Y/n]: ").strip().lower() or "y") != "n"
            common_only = (input("仅扫描 {bin,sbin,usr/bin,usr/sbin}? [Y/n]: ").strip().lower() or "y") != "n"
            cap = input("最多收集多少个(0=不限制) [0]: ").strip() or "0"
            try: max_count = int(cap)
            except Exception: max_count = 0
            logger.info(f"[SCAN] root={root} elf_only={elf_only} skip_so={skip_so} common_only={common_only} cap={max_count}")
            paths = scan_binaries(root, elf_only=elf_only, skip_so=skip_so, common_dirs_only=common_only, max_count=max_count)
            if not paths:
                logger.info("[ERROR] 扫描到 0 个候选，终止。"); logger.close(); return 2
            write_list_file(paths, list_path)
    else:
        logger.info(f"[INFO] 未找到 {list_path}，准备自动扫描生成。")
        choose = input("输入 'y' 继续自动扫描，其他键取消: ").strip().lower()
        if choose == "y":
            root = input("固件根目录 [./squashfs-root]: ").strip() or "./squashfs-root"
            elf_only = (input("仅匹配 ELF 文件? [Y/n]: ").strip().lower() or "y") != "n"
            skip_so = (input("跳过共享库(.so)? [Y/n]: ").strip().lower() or "y") != "n"
            common_only = (input("仅扫描 {bin,sbin,usr/bin,usr/sbin}? [Y/n]: ").strip().lower() or "y") != "n"
            cap = input("最多收集多少个(0=不限制) [0]: ").strip() or "0"
            try: max_count = int(cap)
            except Exception: max_count = 0
            logger.info(f"[SCAN] root={root} elf_only={elf_only} skip_so={skip_so} common_only={common_only} cap={max_count}")
            paths = scan_binaries(root, elf_only=elf_only, skip_so=skip_so, common_dirs_only=common_only, max_count=max_count)
            if not paths:
                logger.info("[ERROR] 扫描到 0 个候选，终止。"); logger.close(); return 2
            write_list_file(paths, list_path)
        else:
            logger.info("[ABORT] 用户取消自动扫描。"); logger.close(); return 2

    # 其他输入
    prefix = (input("QEMU 前缀（按回车使用默认） [qemu-arm-static -L ./squashfs-root]: ").strip() or "qemu-arm-static -L ./squashfs-root")
    env_line = input("额外环境变量（KEY=VAL，多个用逗号分隔）: ").strip()
    timeout_s = input("每个帮助调用超时(秒) [2]: ").strip() or "2"
    out_json = input("输出 JSON 文件名(默认为llm_audit.json) [llm_audit.json]: ").strip() or "llm_audit.json"
    out_csv  = input("输出 CSV 文件名(默认为llm_audit.csv) [llm_audit.csv]: ").strip() or "llm_audit.csv"
    try: timeout = float(timeout_s)
    except Exception: timeout = 2.0

    # 代理 & TLS
    proxy_url = input("HTTPS 代理（如 http://user:pass@host:port，留空不使用）: ").strip()
    global GLOBAL_REQUESTS_PROXIES, GLOBAL_VERIFY_SSL
    GLOBAL_REQUESTS_PROXIES = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
    insecure = input("忽略 TLS 证书校验? [y/N]: ").strip().lower() == 'y'
    GLOBAL_VERIFY_SSL = not insecure

    logger.info(f"[CFG] prefix='{prefix}' timeout={timeout} out_json={out_json} out_csv={out_csv} proxy={'on' if GLOBAL_REQUESTS_PROXIES else 'off'} insecure_ssl={insecure}")
    if env_line:
        logger.info(f"[CFG] extra env: {env_line}")

    # 预检
    if not preflight_check(api_key, base_url, model):
        logger.info("[PREFLIGHT] 连接/鉴权未通过，将在每个批次内继续尝试；若仍失败将使用本地启发式降级。")

    # 读取列表
    try:
        with open(list_path, "r", encoding="utf-8") as f:
            binaries = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except Exception as e:
        logger.info(f"[ERROR] 无法读取列表文件：{e}"); logger.close(); return 2
    if not binaries:
        logger.info("[ERROR] 列表为空。"); logger.close(); return 2
    logger.info(f"[LIST] 将分析 {len(binaries)} 个二进制")

    # 环境变量
    env = os.environ.copy()
    if env_line:
        for kv in [x.strip() for x in env_line.split(",") if x.strip()]:
            if "=" in kv:
                k, v = kv.split("=", 1); env[k.strip()] = v.strip()

    # 探测帮助
    items = []
    for idx, path in enumerate(binaries, 1):
        cmd = build_command(prefix, path)
        logger.info(f"[HELP] ({idx}/{len(binaries)}) 目标={path}")
        help_txt, rc, used = run_help(cmd, env, timeout)
        items.append({"program": path, "help": help_txt.strip(), "return_code": rc, "help_args_used": used})

    # 送入 LLM（10 个一批）
    LLM_SYS = {"role": "system", "content": LLM_SYS_PROMPT}
    all_results: List[Dict] = []
    for i in range(0, len(items), 10):
        group = items[i:i+10]
        batch_id = i//10 + 1
        logger.info(f"[LLM] 批次 #{batch_id} 组装提示（{len(group)} 个程序）")
        lines = []
        for idx, it in enumerate(group, 1):
            lines.append(f"### {idx}) program: {it['program']}")
            lines.append("--- HELP START ---")
            help_s = it["help"]
            if len(help_s) > 12000: help_s = help_s[:12000] + "\n[TRUNCATED]"
            lines.append(help_s)
            lines.append("--- HELP END ---\n")
        user_prompt = "\n".join(lines)
        messages = [LLM_SYS, {"role": "user", "content": user_prompt}]
        try:
            raw = call_openai_chat(api_key, base_url, model, messages, timeout=60.0)
        except Exception as e:
            logger.info(f"[WARN] 批次 #{batch_id} LLM 请求失败：{e} -> 使用启发式降级")
            parsed_objs = heuristic_analyze(group)
            by_name = {r.get("program"): r for r in parsed_objs if isinstance(r, dict)}
            for it in group:
                r = by_name.get(it["program"], {})
                res = {
                    "program": it["program"],
                    "accepts_input": r.get("accepts_input","unknown"),
                    "input_kind": r.get("input_kind","unknown"),
                    "input_flags": r.get("input_flags", []),
                    "stdin_supported": r.get("stdin_supported","unknown"),
                    "notes": r.get("notes",""),
                    "help_args_used": it["help_args_used"],
                }
                res["suggested_afl_cmd"] = suggest_afl(it["program"], res)
                all_results.append(res)
            logger.debug(f"[HEURISTIC-RESP-BATCH-{batch_id}] {json.dumps(parsed_objs)[:4000]}")
            continue

        json_block = extract_json_block(raw) or "[]"
        try:
            parsed = json.loads(json_block)
        except Exception as e:
            logger.info(f"[WARN] 批次 #{batch_id} 解析 JSON 失败：{e}")
            parsed = []

        logger.info(f"[LLM] 批次 #{batch_id} 分析完成，解析到 {len(parsed)} 条结果")
        logger.debug(f"[LLM-RESP-BATCH-{batch_id}] {raw}")

        by_name = {r.get("program"): r for r in parsed if isinstance(r, dict)}
        for it in group:
            r = by_name.get(it["program"], {})
            res = {
                "program": it["program"],
                "accepts_input": r.get("accepts_input", r.get("accepts_file_input", "unknown")),
                "input_kind": r.get("input_kind","unknown"),
                "input_flags": r.get("input_flags", []),
                "stdin_supported": r.get("stdin_supported","unknown"),
                "notes": r.get("notes",""),
                "help_args_used": it["help_args_used"],
            }
            res["suggested_afl_cmd"] = suggest_afl(it["program"], res)
            all_results.append(res)

    # 输出
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"count": len(all_results), "results": all_results}, f, ensure_ascii=False, indent=2)
    fieldnames = ["program","input_kind","accepts_input","input_flags","stdin_supported","suggested_afl_cmd","notes","help_args_used"]
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames); w.writeheader()
        for r in all_results:
            row = dict(r)
            if isinstance(row.get("input_flags"), list):
                row["input_flags"] = " ".join(row["input_flags"])
            w.writerow(row)

    # HTML 报告
    out_html = (out_json.rsplit(".",1)[0] + ".html") if out_json.lower().endswith(".json") else "llm_audit.html"
    try:
        write_html_report(all_results, out_html)
        logger.info(f"[REPORT] 已写出 HTML 报告：{out_html}")
    except Exception as e:
        logger.info(f"[WARN] 生成 HTML 报告失败：{e}")

    logger.info(f"[DONE] 本次共分析 {len(all_results)} 个二进制；JSON={out_json} CSV={out_csv}；详细日志见 {logger.path}")
    logger.close()
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("[ABORT] 用户中断（Ctrl+C）")
        logger.close()
        sys.exit(130)

