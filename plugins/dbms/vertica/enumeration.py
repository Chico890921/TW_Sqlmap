#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getRoles(self, *args, **kwargs):
        warnMsg = "在 Vertica 上無法枚舉用戶角色"
        logger.warning(warnMsg)

        return {}
