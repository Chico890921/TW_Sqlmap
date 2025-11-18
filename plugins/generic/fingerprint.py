#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import readInput
from lib.core.data import logger
from lib.core.enums import OS
from lib.core.exception import SqlmapUndefinedMethod

class Fingerprint(object):
    """
    這個類為插件定義了通用的指紋識別功能。
    """

    def __init__(self, dbms):
        Backend.forceDbms(dbms)

    def getFingerprint(self):
        errMsg = "'getFingerprint' 方法必須在特定的 DBMS 插件中定義"
        #errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def checkDbms(self):
        errMsg = "'checkDbms' 方法必須在特定的 DBMS 插件中定義"
        #errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def checkDbmsOs(self, detailed=False):
        errMsg = "'checkDbmsOs' 方法必須在特定的 DBMS 插件中定義"
        #errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def forceDbmsEnum(self):
        pass

    def userChooseDbmsOs(self):
        warnMsg = "由於某種原因,sqlmap 無法識別後端 DBMS 的操作系統"
        #warnMsg += "the back-end DBMS operating system"
        logger.warning(warnMsg)

        msg = "你是否要提供操作系統？[(W)indows/(l)inux]"

        while True:
            os = readInput(msg, default='W').upper()

            if os == 'W':
                Backend.setOs(OS.WINDOWS)
                break
            elif os == 'L':
                Backend.setOs(OS.LINUX)
                break
            else:
                warnMsg = "無效的值"
                logger.warning(warnMsg)
