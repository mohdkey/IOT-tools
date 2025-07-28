IOT Web Unauthorized Path Scanner
=================================

📌 项目简介：
-------------
本工具用于分析固件中提取的 Web 路径，自动探测对应 Web 页面是否存在未授权访问漏洞，支持页面内容识别、路由映射、跳转检测和5xx错误识别，并生成可视化报告。

👤 作者：XCES@IOTSec-Zone  
🧠 依赖环境：Python 3.6+  

📂 目录结构：
-------------
├── Unauthorized.py           # 主程序脚本  
├── dic/                      # 字典目录  
│   ├── login.txt                 # 登录关键词字典（每行一个）  
│   └── routing.txt           # 逻辑路径 ↔ 物理路径 映射（格式见下）  
├── result.txt                # 探测结果文本  
├── result.html               # 可视化报告（HTML格式）  
├── url.txt                   # 所有URL及状态码（JSON格式）  
├── log.txt                   # 扫描日志文件  

📘 用法说明：
-------------
1. 运行脚本：
   python3 Unauthorized.py
2. 输入 Web 根目录路径（如 ~/firmware/web_root）
3. 输入目标设备地址（如 192.168.0.1，可直接回车默认）

📑 功能说明：
✔ 提取 Web 根目录下所有页面及嵌入 JS 中的路径
✔ 应用 dic/routing.txt 中的路由映射规则
✔ 过滤掉静态资源（如 .js, .png, .jpg 等）
✔ 支持多线程并发 HTTP 探测
✔ 根据响应结果自动分类为：

未授权访问页面：返回 200，且无登录关键词
疑似未授权页面：返回 5xx 错误（可能因参数缺失）
200跳转页面：响应 200 且跳转，但不是跳转到统一登录页
普通页面：返回 200 且含登录关键词
✔ 自动过滤跳转至统一登录页的路径
✔ 输出文本及 HTML 可视化报告
✔ 所有请求日志记录在 log.txt 中

🧾 dic/routing.txt 格式：
每行一条规则，前面是逻辑路径，后面是物理路径，用空格分隔：
/sess-bin/ /cgibin/
/login/    /cgibin/login-cgi/
/ddns/     /cgibin/ddns/
/info/     /home/httpd/info/

🛠 依赖库安装：
bash
复制代码
pip install requests pyfiglet

📎 注意事项：
dic/login 中的关键词用于判断是否为登录页（区分“未授权”和“普通页面”）；
默认使用 GET 请求，请确保设备允许访问；
支持自动检测跳转行为及过滤统一登录页；

📤 输出示例：
result.txt
result.html
url.txt （字典格式：url + 状态码）
log.txt （日志记录所有请求及事件）

