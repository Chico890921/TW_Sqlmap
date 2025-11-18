#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.settings import IS_WIN

def checkDependencies():
    missing_libraries = set()

    for dbmsName, data in DBMS_DICT.items():
        if data[1] is None:
            continue

        try:
            if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                __import__("_mssql")

                pymssql = __import__("pymssql")
                if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                    warnMsg = "'%s' 第三方庫的版本必須大於等於 1.0.2 才能正常工作。請從 '%s' 下載" % (data[1], data[2])
                    #warnMsg += "version >= 1.0.2 to work properly. "
                    #warnMsg += "Download from '%s'" % data[2]
                    logger.warning(warnMsg)
            elif dbmsName == DBMS.MYSQL:
                __import__("pymysql")
            elif dbmsName in (DBMS.PGSQL, DBMS.CRATEDB):
                __import__("psycopg2")
            elif dbmsName == DBMS.ORACLE:
                __import__("oracledb")
            elif dbmsName == DBMS.SQLITE:
                __import__("sqlite3")
            elif dbmsName == DBMS.ACCESS:
                __import__("pyodbc")
            elif dbmsName == DBMS.FIREBIRD:
                __import__("kinterbasdb")
            elif dbmsName == DBMS.DB2:
                __import__("ibm_db_dbi")
            elif dbmsName in (DBMS.HSQLDB, DBMS.CACHE):
                __import__("jaydebeapi")
                __import__("jpype")
            elif dbmsName == DBMS.INFORMIX:
                __import__("ibm_db_dbi")
            elif dbmsName == DBMS.MONETDB:
                __import__("pymonetdb")
            elif dbmsName == DBMS.DERBY:
                __import__("drda")
            elif dbmsName == DBMS.VERTICA:
                __import__("vertica_python")
            elif dbmsName == DBMS.PRESTO:
                __import__("prestodb")
            elif dbmsName == DBMS.MIMERSQL:
                __import__("mimerpy")
            elif dbmsName == DBMS.CUBRID:
                __import__("CUBRIDdb")
            elif dbmsName == DBMS.CLICKHOUSE:
                __import__("clickhouse_connect")
        except:
            warnMsg = "sqlmap 需要 '%s' 第三方庫才能直接連接到數據庫管理系統 '%s'。請從 '%s' 下載" % (data[1], dbmsName, data[2])
            #warnMsg += "in order to directly connect to the DBMS "
            #warnMsg += "'%s'. Download from '%s'" % (dbmsName, data[2])
            logger.warning(warnMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "找到了 '%s' 第三方庫" % data[1]
        logger.debug(debugMsg)

    try:
        __import__("impacket")
        debugMsg = "找到了 'python-impacket' 第三方庫"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap 需要 'python-impacket' 第三方庫以支持帶外接管功能。請從 'https://github.com/coresecurity/impacket' 下載"
        #warnMsg += "out-of-band takeover feature. Download from "
        #warnMsg += "'https://github.com/coresecurity/impacket'"
        logger.warning(warnMsg)
        missing_libraries.add('python-impacket')

    try:
        __import__("ntlm")
        debugMsg = "找到了 'python-ntlm' 第三方庫"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您計劃攻擊一個使用 NTLM 身份驗證的 Web 應用程序,sqlmap 需要 'python-ntlm' 第三方庫。請從 'https://github.com/mullender/python-ntlm' 下載"
        #warnMsg += "if you plan to attack a web application behind NTLM "
        #warnMsg += "authentication. Download from 'https://github.com/mullender/python-ntlm'"
        logger.warning(warnMsg)
        missing_libraries.add('python-ntlm')

    try:
        __import__("httpx")
        debugMsg = "已找到'httpx[http2]'第三方庫"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您計劃攻擊一個使用 WebSocket 的 Web 應用程序,sqlmap 需要 'websocket-client' 第三方庫。請從 'https://pypi.python.org/pypi/websocket-client/' 下載"
        #warnMsg += "if you plan to use HTTP version 2"
        logger.warning(warnMsg)
        missing_libraries.add('httpx[http2]')

    try:
        __import__("websocket._abnf")
        debugMsg = "找到了 'tkinter' 庫"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您計劃運行 GUI 界面,sqlmap 需要 'tkinter' 庫"
        #warnMsg += "if you plan to attack a web application using WebSocket. "
        #warnMsg += "Download from 'https://pypi.python.org/pypi/websocket-client/'"
        logger.warning(warnMsg)
        missing_libraries.add('websocket-client')

    try:
        __import__("tkinter")
        debugMsg = "找到了 'tkinter.ttk' 庫"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您計劃運行 GUI 界面,sqlmap 需要 'tkinter.ttk' 庫"
        #warnMsg += "if you plan to run a GUI"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter')

    try:
        __import__("tkinter.ttk")
        debugMsg = "找到'tkinter.ttk'庫"
        logger.debug(debugMsg)
    except ImportError:
        debugMsg = "找到了 'python-pyreadline' 第三方庫"
        #warnMsg += "if you plan to run a GUI"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter.ttk')

    if IS_WIN:
        try:
            __import__("pyreadline")
            debugMsg = "已找到'python-pyreadline'第三方庫"
            logger.debug(debugMsg)
        except ImportError:
            warnMsg = "sqlmap 需要 'pyreadline' 第三方庫才能在 SQL shell 和 OS shell 中使用 sqlmap 的 TAB 補全和歷史記錄支持功能。請從 'https://pypi.org/project/pyreadline/' 下載"
            #warnMsg += "be able to take advantage of the sqlmap TAB "
            #warnMsg += "completion and history support features in the SQL "
            #warnMsg += "shell and OS shell. Download from "
            #warnMsg += "'https://pypi.org/project/pyreadline/'"
            logger.warning(warnMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "所有依賴項已安裝"
        logger.info(infoMsg)
