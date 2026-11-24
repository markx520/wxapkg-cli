"""wxapkg-cli 统一命令行交互中枢。"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from .archive import extract_archive_to_disk, unpack_archive
from .crypto import DecryptionError, decrypt_stream
from .sniffer import enumerate_active_applet_windows, scan_packages


def cmd_unpack(args: argparse.Namespace) -> int:
    """执行单个 wxapkg 包的纯内存流解密与落盘还原。"""
    pkg_path = Path(args.package).resolve()
    if not pkg_path.is_file():
        print(f"[!] 错误: 指定文件不存在 -> {pkg_path}")
        return 1

    app_id = args.appid
    if not app_id:
        # 尝试从路径推导 wx[0-9a-fA-F]{16}
        match = re.search(r"(wx[0-9a-fA-F]{16})", str(pkg_path))
        if match:
            app_id = match.group(1)
            print(f"[*] 从路径自动提取 AppID: {app_id}")
        else:
            print("[!] 错误: 未提供 --appid 且无法从文件路径中推导 AppID。")
            return 1

    out_dir = Path(args.output).resolve() if args.output else pkg_path.parent / f"{app_id}_extracted"

    print(f"[*] 读取文件: {pkg_path.name} ({pkg_path.stat().st_size} 字节)")
    data = pkg_path.read_bytes()

    try:
        print("[*] 正在执行纯内存流解密...")
        decrypted_stream = decrypt_stream(data, app_id)
        print(f"[+] 内存解密成功，获得原生包流 ({len(decrypted_stream)} 字节)")

        print("[*] 正在解析归档索引并解构文件...")
        files_dict = unpack_archive(decrypted_stream)
        print(f"[+] 成功解析索引，包含 {len(files_dict)} 个文件条目")

        print(f"[*] 正在写入输出目录: {out_dir}")
        saved_paths = extract_archive_to_disk(files_dict, out_dir)
        print(f"[+] 解包完成! 共生成 {len(saved_paths)} 个物理文件。")
        return 0

    except Exception as exc:
        print(f"[!] 处理异常: {exc}")
        return 1


def cmd_scan(args: argparse.Namespace) -> int:
    """扫描系统或指定目录下的 .wxapkg 包。"""
    limit_min = args.minutes
    target_dir = args.dir
    print(f"[*] 扫描最近 {limit_min} 分钟内活跃生成的 .wxapkg 缓存包...")

    pkgs = scan_packages(search_root=target_dir, limit_minutes=limit_min)
    if not pkgs:
        print("[-] 未在对应路径下发现匹配的时间窗口缓存包。")
        return 0

    print(f"[+] 发现 {len(pkgs)} 个匹配的包文件:")
    for item in pkgs[:args.limit]:
        print(f"  - AppID: {item['appid']} | 大小: {item['size']} 字节 | 时间: {item['modified']}")
        print(f"    路径: {item['path']}")
    return 0


def cmd_ps(args: argparse.Namespace) -> int:
    """只读枚举当前桌面运行中的小程序前台窗口。"""
    print("[*] 正在只读扫描前台活动窗口...")
    windows = enumerate_active_applet_windows()
    if not windows:
        print("[-] 未获取到活动窗口列表。")
        return 0

    print(f"[+] 扫描完成，共检测到 {len(windows)} 个有效窗口:")
    for win in windows[:30]:
        print(f"  - PID: {win['pid']} | HWND: {win['hwnd']} | 标题: {win['title']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """命令行主入口。"""
    parser = argparse.ArgumentParser(
        prog="wxapkg",
        description="wxapkg-cli: 微信小程序纯内存流解密与无头离线还原工具",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="子命令列表")

    # unpack 子命令
    p_unpack = subparsers.add_parser("unpack", help="纯内存流解密并解包指定 .wxapkg 文件")
    p_unpack.add_argument("package", help="目标 .wxapkg 文件路径")
    p_unpack.add_argument("-i", "--appid", help="指定小程序 AppID (若省略则尝试从路径解析)")
    p_unpack.add_argument("-o", "--output", help="指定输出解包目录 (若省略则输出到当前包所在同级目录)")
    p_unpack.set_defaults(func=cmd_unpack)

    # scan 子命令
    p_scan = subparsers.add_parser("scan", help="扫描磁盘中最近活跃的 .wxapkg 包")
    p_scan.add_argument("-m", "--minutes", type=int, default=1440, help="扫描时间范围（分钟），默认 1440 (24小时)")
    p_scan.add_argument("-d", "--dir", help="指定自定义搜索根路径")
    p_scan.add_argument("-n", "--limit", type=int, default=20, help="最多显示条数")
    p_scan.set_defaults(func=cmd_scan)

    # ps 子命令
    p_ps = subparsers.add_parser("ps", help="只读枚举当前桌面活动窗口")
    p_ps.set_defaults(func=cmd_ps)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
