#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "在 Virtuoso 上無法枚舉用戶密碼哈希值"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在 Virtuoso 上無法枚舉用戶權限"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "在 Virtuoso 上無法枚舉用戶角色"
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "在 Virtuoso 上無法搜索數據庫"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "在 Virtuoso 上無法搜索表"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "在 Virtuoso 上無法搜索列"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "在 Virtuoso 上無法使用搜索選項"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在 Virtuoso 上無法枚舉 SQL 語句"
        logger.warning(warnMsg)

        return []
