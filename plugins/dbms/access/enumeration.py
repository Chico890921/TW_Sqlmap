#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "在 Microsoft Access 上無法獲取橫幅信息"
        logger.warning(warnMsg)

        return None

    def getCurrentUser(self):
        warnMsg = "在 Microsoft Access 上無法枚舉當前用戶"
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = "在 Microsoft Access 上無法獲取當前數據庫的名稱"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "在 Microsoft Access 上無法測試當前用戶是否為 DBA"
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = "在 Microsoft Access 上無法枚舉用戶"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "在 Microsoft Access 上無法枚舉用戶密碼哈希值"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在 Microsoft Access 上無法枚舉用戶權限"
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "在 Microsoft Access 上無法枚舉數據庫 (僅使用 '--tables')"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = "在 Microsoft Access 上無法搜索數據庫"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "在 Microsoft Access 上無法搜索表格"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "在 Microsoft Access 上無法搜索列"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "在 Microsoft Access 上不可用搜索選項"
        logger.warning(warnMsg)

    def getHostname(self):
        warnMsg = "在 Microsoft Access 上無法枚舉主機名"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在 Microsoft Access 上無法枚舉 SQL 語句"
        logger.warning(warnMsg)

        return []
