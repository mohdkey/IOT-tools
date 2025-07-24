#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
固件Web组件路径提取 + HTTP状态探测 + 可疑页面识别 + HTML报告

功能：
1. 提取Web根目录中的JS文件中硬编码路径 + 所有静态文件路径；
2. 使用dic/login关键词判断是否为登录页（同时用于过滤文件名中包含关键词的文件）；
3. 多线程GET请求：
   - 标记未授权访问页面（无跳转 + 无登录关键词）；
   - 记录所有200响应是否发生跳转（过滤跳转至主页或统一登录页）；
   - 如果多个页面跳转至同一个统一登录页路径，则统一过滤这些跳转页面；
4. 输出 result.txt、url.txt、result.html 报告。
"""

import os
import re
import sys
import json
import requests
from urllib.parse import urljoin, urlparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import pyfiglet

banner = pyfiglet.figlet_format("IOT web Unauthorized")
print("\033[32m" + banner + "\033[0m")
print("Version:1.0")
print("Author: XCES@\033[34mIOTSec-Zone\033[0m")

for i in range(2):
    print("\n")

def load_patterns(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip().lower() for line in f if line.strip()]

def is_excluded_url(url):
    excluded_exts = ('.js', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', '.css')
    return url.lower().endswith(excluded_exts)

def extract_routes_from_js(web_root_dir):
    routes = set()
    excluded_exts = ('.js', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', '.css')
    for root, _, files in os.walk(web_root_dir):
        for filename in files:
            if not filename.lower().endswith('.js'):
                continue
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                print(f"无法读取JS文件 {file_path}: {e}")
                continue
            pattern = re.compile(r'/[0-9A-Za-z_/.*%:\-]+')
            for match in pattern.findall(content):
                if match.startswith("//") or match.startswith("/*"):
                    continue
                if any(match.lower().endswith(ext) for ext in excluded_exts):
                    continue
                routes.add(match)
    return routes

web_root_dir = os.path.expanduser(input("请输入Web根目录路径: ").strip())
if not os.path.isdir(web_root_dir):
    print("提供的Web根目录无效或不存在！")
    sys.exit(1)

target = input("请输入目标IP或网址（如192.168.0.1）: ").strip()
if not target.startswith("http://"):
    base_url = f"http://{target}"
else:
    base_url = target
base_url = base_url.rstrip("/")

print("\n正在加载关键词...")
keywords = load_patterns("dic/login")

print("\n正在提取路径...")
excluded_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', '.css', '.js'}
all_routes = set()
for root, _, files in os.walk(web_root_dir):
    for filename in files:
        ext = os.path.splitext(filename)[1].lower()
        if ext in excluded_exts:
            continue
        filename_lower = filename.lower()
        if any(kw in filename_lower for kw in keywords):
            continue
        full_path = os.path.join(root, filename)
        rel_path = os.path.relpath(full_path, web_root_dir)
        url_path = '/' + rel_path.replace('\\', '/').replace(' ', '%20')
        if not is_excluded_url(url_path):
            all_routes.add(url_path)

js_routes = extract_routes_from_js(web_root_dir)
all_routes.update(js_routes)
all_routes = sorted(all_routes)
print(f"共提取 {len(all_routes)} 个路径\n")

results = []
unauth_pages, redirect_pages, normal_pages = [], [], []
url_status_list = []
redirect_target_counter = defaultdict(list)


def fetch_url(path):
    url = urljoin(base_url, path)
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        content = response.text.lower()
        status_code = response.status_code
        final_url = response.url
        redirected = url.rstrip('/') != final_url.rstrip('/')
        has_login_kw = any(kw in content for kw in keywords)
        return (url, status_code, final_url, has_login_kw, redirected)
    except:
        return (url, None, None, False, False)

with ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(fetch_url, all_routes))

# 统计所有跳转目标频率
for url, status, final_url, has_kw, redirected in results:
    if status and redirected:
        parsed = urlparse(final_url)
        path = parsed.path.lower()
        if path.strip('/') in ('', 'index.html') or any(kw in path for kw in keywords):
            continue
        redirect_target_counter[final_url].append(url)

# 提取跳转到统一登录页的目标地址
login_redirect_targets = set()
for target, sources in redirect_target_counter.items():
    if len(sources) >= 3:
        login_redirect_targets.add(target)

# 二次处理分类
for url, status, final_url, has_kw, redirected in results:
    if status and status != 404:
        url_status_list.append({"url": url, "status": status})
    if not status or not (200 <= status < 300):
        continue
    if is_excluded_url(url):
        continue
    if redirected:
        if final_url in login_redirect_targets:
            continue  # 统一登录页跳转过滤
        redirect_pages.append(f"{url} → {final_url}")
        continue
    if not has_kw:
        unauth_pages.append(url)
    else:
        normal_pages.append(url)

with open("result.txt", 'w', encoding='utf-8') as f:
    f.write("未授权访问页面：\n")
    f.writelines(url + "\n" for url in unauth_pages)
    f.write("\n200跳转页面：\n")
    f.writelines(url + "\n" for url in redirect_pages)
    f.write("\n普通页面：\n")
    f.writelines(url + "\n" for url in normal_pages)

with open("url.txt", 'w', encoding='utf-8') as f:
    json.dump(url_status_list, f, indent=2, ensure_ascii=False)

with open("result.html", 'w', encoding='utf-8') as f:
    f.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>扫描报告</title></head><body>')
    f.write('<h3 style="color:red;">未授权访问页面</h3><ul>')
    for url in unauth_pages:
        f.write(f'<li><a href="{url}" target="_blank">{url}</a></li>')
    f.write('</ul><h3 style="color:blue;">200跳转页面</h3><ul>')
    for url in redirect_pages:
        f.write(f'<li>{url}</li>')
    f.write('</ul><h3 style="color:green;">普通页面</h3><ul>')
    for url in normal_pages:
        f.write(f'<li><a href="{url}" target="_blank">{url}</a></li>')
    f.write('</ul></body></html>')

print(f"\n共 {len(unauth_pages) + len(redirect_pages) + len(normal_pages)} 个路径返回2xx，已保存至 result.txt 和 result.html")
