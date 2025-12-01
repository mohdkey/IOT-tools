import sys
import time
import math
import threading
from collections import Counter

import serial
import serial.tools.list_ports

# 尝试使用颜色输出（colorama：终端颜色控制库，用来给文字加颜色/样式）
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    USE_COLOR = True
except ImportError:
    USE_COLOR = False

    class Fore:
        CYAN = ""
        GREEN = ""
        YELLOW = ""
        RED = ""
        RESET = ""

    class Style:
        RESET_ALL = ""


# 全局输出锁：防止接收线程和主线程同时往终端写导致文字交叉
print_lock = threading.Lock()

# ========= 波特率检测相关 =========

COMMON_BAUDRATES = [
    300, 600, 1200, 2400,
    4800, 7200, 9600, 14400,
    19200, 28800, 31250, 38400,
    56000, 57600, 115200, 128000,
    153600, 230400, 256000, 460800,
    500000, 512000, 576000, 921600,
    1000000, 1152000, 1500000,
    2000000, 2500000, 3000000
]


def calc_entropy(data: bytes) -> float:
    """计算信息熵(entropy，用来衡量数据随机程度的指标)"""
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for c in counter.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def printable_ratio(data: bytes) -> float:
    """
    计算可打印字符比例：
    - 先按 UTF-8 解码
    - 用 str.isprintable() 判断是否可显示（包括中文）
    """
    if not data:
        return 0.0
    text = data.decode("utf-8", errors="ignore")
    if not text:
        return 0.0

    printable = 0
    total = 0
    for ch in text:
        total += 1
        if ch in "\r\n\t":
            printable += 1
        elif ch.isprintable():
            printable += 1

    return printable / max(1, total)


def log_pattern_score(text: str) -> float:
    """
    “日志气质分”：
    用一些启发式(heuristic，经验规则，不是严格数学证明的算法)来判断这段文本像不像日志。
    返回一个 0.5 ~ 2.0 的系数，越像典型日志格式分越高。
    """
    if not text:
        return 0.5

    score = 1.0

    # 有数字：时间戳 / 端口 / IP 等都大量用数字
    if any(ch.isdigit() for ch in text):
        score += 0.2

    # 有典型日志符号：[]:.@-/ 之类
    hits = 0
    for ch in "[]:.@-/":
        if ch in text:
            hits += 1
    score += min(hits * 0.05, 0.3)  # 最多 +0.3

    # 常见日志级别关键字
    upper = text.upper()
    for kw in ("INFO", "WARN", "ERROR", "ERR", "DEBUG"):
        if kw in upper:
            score += 0.3
            break

    # IP / URL 迹象
    lower = text.lower()
    if "ip:" in lower or "http" in lower:
        score += 0.2

    # 约束范围，防止太夸张
    score = max(0.5, min(score, 2.0))
    return score


def detect_baudrate(port_name: str, top_n: int = 5):
    """
    自动扫描一组常见波特率：
    - 对每个波特率读取一段数据
    - 计算可打印比例 + 文本长度 + 熵 + 日志气质分
    - 综合评分：score = printable_ratio * length_weight * log_pattern_score
      （length_weight 随文本长度增长，最多到 1）
    返回按得分排序的前 top_n 个候选波特率
    """
    print(f"\n开始扫描串口 {port_name} 的可能波特率...\n")

    results = []

    for baud in COMMON_BAUDRATES:
        try:
            print(f"尝试波特率：{baud} ...")
            ser = serial.Serial(port_name, baud, timeout=0.8)

            # 先清一下缓冲区，然后等一会儿收新数据
            ser.reset_input_buffer()
            time.sleep(0.8)
            data = ser.read(1024)
            ser.close()

            if not data:
                print("    ✖ 无数据")
                results.append((baud, 0.0, 0.0, 0, 0.0, 1.0, ""))
                continue

            ent = calc_entropy(data)
            pr = printable_ratio(data)
            text = data.decode("utf-8", errors="ignore")
            preview = text.replace("\r", "\\r").replace("\n", "\\n")
            length = len(text)

            # 长度权重：字符越多越好，40 个字符视为“足够长”
            length_weight = min(length / 40.0, 1.0)

            # 日志气质分：越像“标准日志格式”分越高
            pattern = log_pattern_score(text)

            # 综合得分：原来的基础上再乘一个“像日志”的权重
            score = pr * length_weight * pattern

            print(f"    信息熵(entropy)   = {ent:.2f}")
            print(f"    可打印字符比例    = {pr * 100:.1f}%")
            print(f"    文本长度          = {length}")
            print(f"    日志气质(pattern) = {pattern:.2f}")
            print(f"    综合得分(score)   = {score:.3f}")
            print(f"    预览：{preview[:80]}")

            results.append((baud, pr, ent, length, score, pattern, preview))

        except Exception as e:
            print(f"    ✖ 打开或读取失败: {e}")
            results.append((baud, 0.0, 0.0, 0, 0.0, 1.0, ""))

    print("\n================ 波特率检测总结 ================")
    for baud, pr, ent, length, score, pattern, preview in results:
        print(
            f"  波特率 {baud:<7} | 可打印 {pr * 100:5.1f}% | 熵 {ent:4.2f} | "
            f"长度 {length:4d} | 模式 {pattern:4.2f} | 得分 {score:5.3f} | 预览: {preview[:40]}"
        )

    # 挑选得分>阈值的作为候选，顺便要求有一定长度
    candidates = [
        r for r in results
        if r[4] > 0.05 and r[3] >= 4  # r[4]=score, r[3]=length
    ]
    if not candidates:
        print("\n❌ 没有找到可靠的候选波特率（可能无输出或不是文本）。")
        return []

    # 按综合得分从高到低排序
    candidates.sort(key=lambda x: x[4], reverse=True)
    candidates = candidates[:top_n]

    print("\n🎯 候选波特率列表（按综合得分从高到低）：")
    for idx, (baud, pr, ent, length, score, pattern, preview) in enumerate(candidates):
        print(
            f"  [{idx}] 波特率={baud:<7} 得分={score:5.3f} "
            f"可打印={pr * 100:5.1f}% 长度={length:4d} 模式={pattern:4.2f}  预览: {preview[:40]}"
        )

    print("================================================\n")
    return candidates


# ========= 串口终端相关 =========

def list_serial_ports():
    """列出当前所有可用串口"""
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("未发现任何串口设备。")
        sys.exit(0)

    print("可用串口：")
    for i, p in enumerate(ports):
        print(f"  {i}: {p.device}  -  {p.description}")
    return ports


def choose_port(ports):
    """选择串口"""
    while True:
        try:
            index = int(input("\n请选择串口编号（数字）："))
            if 0 <= index < len(ports):
                return ports[index].device
            else:
                print("编号超出范围，请重新输入。")
        except ValueError:
            print("请输入数字编号。")


def choose_baud_from_candidates(candidates):
    """
    从自动检测出来的候选波特率中选择一个
    如果直接回车，默认选第 0 个（得分最高）
    """
    if not candidates:
        return None

    default_baud = candidates[0][0]
    s = input(f"请选择候选波特率编号（直接回车默认 [0] {default_baud}）：").strip()
    if not s:
        print(f"使用默认波特率：{default_baud}")
        return default_baud
    try:
        idx = int(s)
        if 0 <= idx < len(candidates):
            baud = candidates[idx][0]
            print(f"已选择波特率：{baud}")
            return baud
        else:
            print("编号超出范围，使用默认。")
            return default_baud
    except ValueError:
        print("输入非法，使用默认。")
        return default_baud


def manual_choose_baudrate():
    """手动选择波特率(baud rate，每秒传输的比特数)"""
    common_baud = [9600, 19200, 38400, 57600, 115200, 1500000]
    print("\n常用波特率：", ", ".join(str(b) for b in common_baud))
    s = input("请输入波特率（直接回车默认 115200）：").strip()
    if not s:
        return 115200
    try:
        return int(s)
    except ValueError:
        print("输入非法，使用默认 115200。")
        return 115200


def reader_thread_func(ser, stop_event: threading.Event):
    """
    串口接收线程：
    - 不断从串口读取数据
    - 每次读到数据就带时间戳打印（类似 MobaXterm 串口窗口）
    stop_event：线程同步事件(Event，用来在多个线程之间安全传递“停止”信号)
    """
    while not stop_event.is_set():
        try:
            data = ser.read(ser.in_waiting or 1)
            if data:
                text = data.decode("utf-8", errors="replace")
                ts = time.strftime("%H:%M:%S")
                with print_lock:
                    if USE_COLOR:
                        sys.stdout.write(
                            f"{Fore.CYAN}[{ts}] {Fore.GREEN}{text}{Style.RESET_ALL}"
                        )
                    else:
                        sys.stdout.write(f"[{ts}] {text}")
                    sys.stdout.flush()
        except serial.SerialException as e:
            with print_lock:
                if USE_COLOR:
                    print(f"\n{Fore.RED}串口异常：{e}{Style.RESET_ALL}")
                else:
                    print(f"\n串口异常：{e}")
            stop_event.set()
            break
        except Exception as e:
            with print_lock:
                print(f"\n接收线程异常：{e}")
            stop_event.set()
            break


def start_terminal(port_name: str, baudrate: int):
    """启动命令行版“小型串口终端”"""
    print(f"\n即将打开串口：{port_name}, 波特率：{baudrate} ...")

    try:
        ser = serial.Serial(port_name, baudrate, timeout=0.1)
    except Exception as e:
        print(f"打开串口失败：{e}")
        return

    print("\n串口已打开。")
    print("提示：")
    print("  - 串口收到的数据会实时显示在屏幕上；")
    print("  - 在这里输入内容并回车，会发送到串口（默认会附加 \\r\\n）；")
    print("  - 输入 /quit 回车 可以退出程序；\n")

    stop_event = threading.Event()
    t = threading.Thread(target=reader_thread_func, args=(ser, stop_event), daemon=True)
    t.start()

    try:
        while not stop_event.is_set():
            try:
                line = input()
            except EOFError:
                # 终端被关闭等情况
                break

            if line.strip() == "/quit":
                with print_lock:
                    print("准备退出...")
                stop_event.set()
                break

            try:
                send_bytes = (line + "\r\n").encode("utf-8")
                ser.write(send_bytes)

                # 回显自己发出的命令，带 [TX] 标记
                ts = time.strftime("%H:%M:%S")
                with print_lock:
                    if USE_COLOR:
                        print(f"{Fore.YELLOW}[{ts}] [TX] {line}{Style.RESET_ALL}")
                    else:
                        print(f"[{ts}] [TX] {line}")
            except serial.SerialException as e:
                with print_lock:
                    print(f"发送失败，串口异常：{e}")
                stop_event.set()
                break
    finally:
        stop_event.set()
        time.sleep(0.2)
        try:
            ser.close()
        except Exception:
            pass
        print("串口已关闭，程序结束。")


def main():
    print("=== 串口波特率智能检测 + 简易串口终端 ===\n")

    # 1. 选择串口
    ports = list_serial_ports()
    port_name = choose_port(ports)

    # 2. 问你要不要先自动扫描波特率
    choice = input("\n是否需要先自动扫描波特率？(y/N)：").strip().lower()

    if choice in ("y", "yes"):
        # 自动扫描
        candidates = detect_baudrate(port_name)
        if candidates:
            baudrate = choose_baud_from_candidates(candidates)
        else:
            print("\n自动检测失败/不可靠，改为手动输入波特率。")
            baudrate = manual_choose_baudrate()
    else:
        # 直接手动输入波特率
        baudrate = manual_choose_baudrate()

    # 3. 进入命令行版“小型串口终端”
    start_terminal(port_name, baudrate)


if __name__ == "__main__":
    main()
