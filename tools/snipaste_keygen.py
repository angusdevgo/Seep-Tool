# -*- coding: utf-8 -*-
"""Snipaste Keygen Bridge for Seep-Tool
通过标准输出向 C# WebServer 提供即时激活码生成与模拟校验服务。
"""
import sys
import os
import json

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
snipaste_src = os.path.join(base_dir, "..", "Snipaste", "src")
sys.path.insert(0, snipaste_src)

try:
    from keygen import algo
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    kp_path = os.path.join(base_dir, "keypair.bin")
    if not os.path.exists(kp_path):
        kp_path = os.path.join(base_dir, "..", "Snipaste", "tools", "keypair.bin")

    kp = open(kp_path, "rb").read()
    priv = Ed25519PrivateKey.from_private_bytes(kp[:32])
    guid = algo.read_machine_guid()
    mid = algo.expected_machineid(guid)

    days = 366
    if len(sys.argv) > 1:
        try:
            days = int(sys.argv[1])
        except:
            pass

    code = algo.build_activation_code(priv, name="Seep User", email="seep@tool.local", days=days, machine_guid=guid)
    out = {
        "ok": True,
        "code": code,
        "guid": guid,
        "mid": mid,
        "days": days
    }
    print(json.dumps(out))
except Exception as e:
    print(json.dumps({"ok": False, "error": str(e)}))
