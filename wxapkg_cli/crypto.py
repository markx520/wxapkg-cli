"""纯内存流解密引擎，不产生任何磁盘临时文件。"""

from __future__ import annotations

import hashlib
from typing import Optional

try:
    from Crypto.Cipher import AES
except ImportError:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        AES = None


HEADER_MAGIC = b"V1MMWX"
SALT_SEED = b"saltiest"
AES_IV = b"the iv: 16 bytes"
PBKDF2_ROUNDS = 1000
DERIVED_KEY_LENGTH = 32


class DecryptionError(Exception):
    """解密过程中的异常基类。"""
    pass


def _derive_aes_key(app_id: str) -> bytes:
    """使用 PBKDF2 算法从小程序 AppID 派生 32 字节 AES 密钥。"""
    if not app_id:
        raise DecryptionError("AppID 不能为空。")
    return hashlib.pbkdf2_hmac(
        "sha1",
        app_id.encode("utf-8"),
        SALT_SEED,
        PBKDF2_ROUNDS,
        DERIVED_KEY_LENGTH,
    )


def decrypt_stream(data: bytes, app_id: str) -> bytes:
    """在纯内存中解密 wxapkg 二进制数据流。

    参数:
        data: 原始 wxapkg 文件字节流。
        app_id: 小程序 AppID (例如 wx1234567890abcdef)。

    返回:
        解密后的原生二进制包数据（以 0xBE 开头）。
    """
    if not data:
        raise DecryptionError("待解密数据为空。")

    # 如果已经是解密状态（原生包以 0xBE 开头），直接返回
    if data[0:1] == b"\xbe":
        return data

    if len(data) < 14:
        raise DecryptionError(f"数据长度过短 ({len(data)} 字节)，无法识别包格式。")

    # 校验并剔除 6 字节加密标识头
    if data.startswith(HEADER_MAGIC):
        body_data = data[6:]
    else:
        # 部分旧格式或未带标识头，保持原样处理
        body_data = data

    if len(body_data) < 1024:
        raise DecryptionError(f"加密包体长度不足 1024 字节 ({len(body_data)} 字节)。")

    if AES is None:
        raise DecryptionError("未检测到 pycryptodome 模块，请先安装：pip install pycryptodome")

    # 1. 派生密钥并解密前 1024 字节（取有效 1023 字节）
    key = _derive_aes_key(app_id)
    cipher = AES.new(key, AES.MODE_CBC, AES_IV)
    decrypted_head = cipher.decrypt(body_data[:1024])[:1023]

    # 2. 对后续字节流执行动态异或解密
    xor_byte = ord(app_id[-2]) if len(app_id) >= 2 else 0x66
    tail_bytes = body_data[1024:]
    decrypted_tail = bytes(b ^ xor_byte for b in tail_bytes)

    # 3. 内存拼接返回
    decrypted_data = decrypted_head + decrypted_tail
    if not decrypted_data.startswith(b"\xbe"):
        raise DecryptionError("解密失败：解密后包头魔数不匹配（非 0xBE），请确认 AppID 是否正确。")

    return decrypted_data
