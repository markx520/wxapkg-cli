"""wxapkg 归档包结构内存解析与安全解构模块。"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple


class ArchiveFormatError(Exception):
    """归档包结构格式异常。"""
    pass


def unpack_archive(data: bytes) -> Dict[str, bytes]:
    """在纯内存中解析已解密的 wxapkg 二进制包，返回文件名与文件内容映射。

    参数:
        data: 已解密的原生 wxapkg 字节流（以 0xBE 开头）。

    返回:
        字典映射：{内部相对路径: 文件字节内容}
    """
    if len(data) < 18:
        raise ArchiveFormatError(f"归档数据长度过小 ({len(data)} 字节)。")

    # 1. 校验首字节魔数
    magic_head = data[0]
    if magic_head != 0xBE:
        raise ArchiveFormatError(f"无效的包头魔数: 0x{magic_head:02x}，期望 0xBE。")

    # 2. 解析固定包头元信息
    # 结构: [1B magic] [4B info1] [4B index_len] [4B body_len] [1B magic_mid] [4B file_count]
    _info1 = struct.unpack(">I", data[1:5])[0]
    index_length = struct.unpack(">I", data[5:9])[0]
    body_length = struct.unpack(">I", data[9:13])[0]

    magic_mid = data[13]
    if magic_mid != 0xED:
        raise ArchiveFormatError(f"无效的索引区标记: 0x{magic_mid:02x}，期望 0xED。")

    file_count = struct.unpack(">I", data[14:18])[0]
    cursor = 18

    # 3. 解析索引条目列表
    index_entries: List[Tuple[str, int, int]] = []
    total_len = len(data)

    for _ in range(file_count):
        if cursor + 4 > total_len:
            break
        name_length = struct.unpack(">I", data[cursor : cursor + 4])[0]
        cursor += 4

        if cursor + name_length > total_len:
            break
        raw_name = data[cursor : cursor + name_length]
        cursor += name_length

        name = raw_name.decode("utf-8", errors="replace")

        if cursor + 8 > total_len:
            break
        file_offset = struct.unpack(">I", data[cursor : cursor + 4])[0]
        cursor += 4
        file_size = struct.unpack(">I", data[cursor : cursor + 4])[0]
        cursor += 4

        index_entries.append((name, file_offset, file_size))

    # 4. 提取各文件内容流
    extracted_files: Dict[str, bytes] = {}
    for raw_path, offset, size in index_entries:
        if offset < 0 or size < 0 or offset + size > total_len:
            continue
        # 统一清洗规范化路径，防范目录遍历
        clean_path = raw_path.replace("\\", "/").lstrip("/")
        parts = [p for p in clean_path.split("/") if p and p != "." and p != ".."]
        safe_rel_path = "/".join(parts) if parts else "unnamed_resource"

        extracted_files[safe_rel_path] = data[offset : offset + size]

    return extracted_files


def extract_archive_to_disk(
    extracted_files: Dict[str, bytes],
    output_dir: str | Path,
) -> List[str]:
    """将内存中已解构的文件映射批量落盘至目标文件夹。

    参数:
        extracted_files: 文件字典 {相对路径: 字节内容}
        output_dir: 目标根目录

    返回:
        成功写入的文件物理路径列表。
    """
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    saved_paths: List[str] = []
    for rel_path, content in extracted_files.items():
        target_file = out_root / rel_path
        # 安全防御：防范上跳至根目录之外
        try:
            target_file.resolve().relative_to(out_root)
        except ValueError:
            continue

        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(content)
        saved_paths.append(str(target_file))

    return saved_paths
