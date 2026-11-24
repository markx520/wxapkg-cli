"""免注入窗口只读枚举与本地包拓扑扫描模块。"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


def find_applet_directories() -> List[Path]:
    """发现当前 Windows 宿主机上常见的微信小程序缓存存储路径。"""
    candidates = [
        # 微信 4.x Radium 架构
        Path(os.path.expandvars(r"%APPDATA%\Tencent\xwechat\radium\users")),
        Path(os.path.expandvars(r"%APPDATA%\Tencent\xwechat\radium\Applet\packages")),
        # 微信 3.x 传统文档目录
        Path(os.path.expanduser(r"~\Documents\WeChat Files\Applet")),
    ]
    existing = [p for p in candidates if p.exists()]
    return existing


def scan_packages(
    search_root: Optional[str | Path] = None,
    limit_minutes: int = 1440,
) -> List[Dict[str, str | int]]:
    """扫描指定或系统目录下最近活跃生成的 .wxapkg 包。

    参数:
        search_root: 指定搜索路径，若为空则自动使用系统默认路径。
        limit_minutes: 时间窗口（分钟），默认 24 小时内。

    返回:
        包信息列表，包含路径、大小、修改时间、推导 AppID。
    """
    roots = [Path(search_root)] if search_root else find_applet_directories()
    results: List[Dict[str, str | int]] = []
    now = time.time()
    time_threshold = now - (limit_minutes * 60)

    appid_pattern = re.compile(r"(wx[0-9a-fA-F]{16})")

    for root in roots:
        if not root.exists():
            continue
        for pkg_path in root.glob("**/__APP__.wxapkg"):
            try:
                mtime = pkg_path.stat().st_mtime
                if mtime >= time_threshold:
                    match = appid_pattern.search(str(pkg_path))
                    inferred_appid = match.group(1) if match else "unknown"
                    results.append({
                        "path": str(pkg_path),
                        "appid": inferred_appid,
                        "size": pkg_path.stat().st_size,
                        "mtime": mtime,
                        "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)),
                    })
            except (OSError, PermissionError):
                continue

    # 按修改时间倒序排列
    results.sort(key=lambda x: int(x["mtime"]), reverse=True)
    return results


def enumerate_active_applet_windows() -> List[Dict[str, str | int]]:
    """通过 Windows API 只读枚举当前桌面运行中的小程序前台窗口（零注入、零挂钩）。"""
    if sys.platform != "win32":
        return []

    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    EnumWindows = user32.EnumWindows
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    GetWindowTextW = user32.GetWindowTextW
    GetWindowTextLengthW = user32.GetWindowTextLengthW
    IsWindowVisible = user32.IsWindowVisible
    GetWindowThreadProcessId = user32.GetWindowThreadProcessId

    found_windows: List[Dict[str, str | int]] = []

    def enum_callback(hwnd, lparam):
        if not IsWindowVisible(hwnd):
            return True
        length = GetWindowTextLengthW(hwnd)
        if length == 0:
            return True
        buff = ctypes.create_unicode_buffer(length + 1)
        GetWindowTextW(hwnd, buff, length + 1)
        title = buff.value.strip()

        if not title:
            return True

        pid = wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

        # 简单过滤常见微信窗口特征（如带有标题的小程序运行窗口）
        found_windows.append({
            "hwnd": hwnd,
            "pid": pid.value,
            "title": title,
        })
        return True

    EnumWindows(EnumWindowsProc(enum_callback), 0)
    return found_windows
