#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUndefinedMethod

class Connector(object):
    """
    這個類為插件定義了通用的數據庫管理系統協議功能。
    """

    def __init__(self):
        self.connector = None
        self.cursor = None
        self.hostname = None

    def initConnection(self):
        self.user = conf.dbmsUser or ""
        self.password = conf.dbmsPass or ""
        self.hostname = conf.hostname
        self.port = conf.port
        self.db = conf.dbmsDb

    def printConnected(self):
        if self.hostname and self.port:
            infoMsg = "連接到 %s 服務器 '%s:%d' 成功" % (conf.dbms, self.hostname, self.port)
            logger.info(infoMsg)

    def closed(self):
        if self.hostname and self.port:
            infoMsg = "連接到 %s 服務器 '%s:%d' 已關閉" % (conf.dbms, self.hostname, self.port)
            logger.info(infoMsg)

        self.connector = None
        self.cursor = None

    def initCursor(self):
        self.cursor = self.connector.cursor()

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.connector:
                self.connector.close()
        except Exception as ex:
            logger.debug(ex)
        finally:
            self.closed()

    def checkFileDb(self):
        if not os.path.exists(self.db):
            errMsg = "提供的數據庫文件 '%s' 不存在" % self.db
            raise SqlmapFilePathException(errMsg)

    def connect(self):
        errMsg = "在具體的 DBMS 插件中必須定義 'connect' 方法"
        #errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def fetchall(self):
        errMsg = "在具體的 DBMS 插件中必須定義 'fetchall' 方法"
        #errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def execute(self, query):
        errMsg = "在具體的 DBMS 插件中必須定義 'execute' 方法"
        #errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def select(self, query):
        errMsg = "在具體的 DBMS 插件中必須定義 'select' 方法"
        #errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)
