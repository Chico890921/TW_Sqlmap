#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import sys
import time

PYVERSION = sys.version.split()[0]

if PYVERSION < "2.6":
    sys.exit("[%s] [嚴重] 檢測到不兼容的 Python 版本 ('%s')。要成功運行 sqlmap，您需要使用版本 2.6、2.7 或 3.x（請訪問 'https://www.python.org/downloads/'）" % (time.strftime("%X"), PYVERSION))

errors = []
extensions = ("bz2", "gzip", "pyexpat", "ssl", "sqlite3", "zlib")
for _ in extensions:
    try:
        __import__(_)
    except ImportError:
        errors.append(_)

if errors:
    errMsg = "[%s] [CRITICAL] 缺少一個或多個核心擴展 (%s)," % (time.strftime("%X"), ", ".join("'%s'" % _ for _ in errors))
    errMsg += "很可能是因為當前版本的 Python 沒有正確的開發包構建"
    #errMsg += "built without appropriate dev packages"
    sys.exit(errMsg)
