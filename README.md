# IOT-tools
IOT安全学习过程中自己写的一些脚本

## IOT WEB Unauthorized
探测固件web未授权页面脚本，具体使用方式见
https://github.com/mohdkey/IOT-tools/blob/main/IOT%20WEB%20Unauthorized/readme.txt

## 010 editor 提取uImage
uImage.bt

## yun_tools
输入aws云或ali云的aksk检验权限以及资产并生成报告

## fuzz_iofile_scan
目的：筛选出固件中的能直接通过AFL++进行fuzz的二进制文件
详见https://github.com/mohdkey/IOT-tools/blob/main/fuzz_iofile_scan/README.md

## serial_terminal.py

### 串口波特率智能检测 + 简易终端工具

这是一个用 Python 写的**命令行串口调试工具**，集成了：

1. **串口波特率智能扫描**（可选）  
2. **手动选择波特率**  
3. **简单的串口终端**：  
   - 实时打印串口日志  
   - 命令行输入指令并发送给设备  
   - 显示带时间戳的本地 `[TX]` 回显  

非常适合用于给嵌入式设备、开发板、模组做串口调试。

---

### 功能一览

- 🔍 **自动波特率扫描（baudrate detection）**  
  - 遍历一系列常见波特率  
  - 对每个波特率读取一小段数据  
  - 计算：
    - 信息熵（entropy，用来衡量数据随机程度的一个数学指标）  
    - 可打印字符比例（printable ratio，数据中能显示成文字的部分占比）  
    - 文本长度  
  - 结合这些指标给每个波特率打一个“综合得分(score)”  
  - 选出若干“最像是正常日志/文本”的波特率作为候选  

- 🧪 **人工确认波特率**  
  - 自动扫描后给出一个候选列表（排序好的）  
  - 你可以从中选择一个，或者改用手动输入  

- 💻 **命令行版“小型串口终端”**  
  - 串口收到的数据会实时打印出来，并附带本机时间戳  
  - 在命令行输入一行内容并回车会发送到设备（自动附加 `\r\n`）  
  - 每条你发出去的命令都会以 `[TX]` 形式回显，方便在滚动日志中区分  

---

### 环境要求

- Python 3.7 及以上版本
- 已安装以下第三方库：
  - `pyserial`：串口访问库  
  - `colorama`（可选）：在 Windows 等终端中实现彩色输出

安装依赖：

```bash
pip install pyserial colorama
