#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import MSSQL_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MSSQL)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("Web 服務器", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "後端 DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        blank = " " * 15
        value += "活動指紋: %s" % actVer

        if kb.bannerFp:
            release = kb.bannerFp.get("dbmsRelease")
            version = kb.bannerFp.get("dbmsVersion")
            servicepack = kb.bannerFp.get("dbmsServicePack")

            if release and version and servicepack:
                banVer = "%s %s " % (DBMS.MSSQL, release)
                banVer += "Service Pack %s " % servicepack
                banVer += "version %s" % version

                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(MSSQL_ALIASES):
            setDbms("%s %s" % (DBMS.MSSQL, Backend.getVersion()))

            self.getBanner()

            Backend.setOs(OS.WINDOWS)

            return True

        infoMsg = "testing %s" % DBMS.MSSQL
        logger.info(infoMsg)

        # 注意:直接連接到 Microsoft SQL Server 數據庫時,SELECT LEN(VERSION)=LEN(VERSION) FROM DUAL 不起作用
        # work connecting directly to the Microsoft SQL Server database
        if conf.direct:
            result = True
        else:
            result = inject.checkBooleanExpression("UNICODE(SQUARE(NULL)) IS NULL")

        if result:
            infoMsg = "確認 %s" % DBMS.MSSQL
            logger.info(infoMsg)

            for version, check in (
                ("Azure", "@@VERSION LIKE '%Azure%'"),
                ("2025", "CHARINDEX('17.0.',@@VERSION)>0"),
                ("2022", "GREATEST(NULL,NULL) IS NULL"),
                ("2019", "CHARINDEX('15.0.',@@VERSION)>0"),
                ("2017", "TRIM(NULL) IS NULL"),
                ("2016", "ISJSON(NULL) IS NULL"),
                ("2014", "CHARINDEX('12.0.',@@VERSION)>0"),
                ("2012", "CONCAT(NULL,NULL)=CONCAT(NULL,NULL)"),
                ("2008", "SYSDATETIME()=SYSDATETIME()"),
                ("2005", "XACT_STATE()=XACT_STATE()"),
                ("2000", "HOST_NAME()=HOST_NAME()"),
            ):
                result = inject.checkBooleanExpression(check)

                if result:
                    Backend.setVersion(version)
                    break

            if Backend.getVersion():
                setDbms("%s %s" % (DBMS.MSSQL, Backend.getVersion()))
            else:
                setDbms(DBMS.MSSQL)

            self.getBanner()

            Backend.setOs(OS.WINDOWS)

            return True
        else:
            warnMsg = "後端 DBMS 不是 %s" % DBMS.MSSQL
            logger.warning("警告:%s" % warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs() and Backend.getOsVersion() and Backend.getOsServicePack():
            return

        if not Backend.getOs():
            Backend.setOs(OS.WINDOWS)

        if not detailed:
            return

        infoMsg = "識別後端 DBMS 操作系統版本和服務包"
        #infoMsg += "version and service pack"
        logger.info(infoMsg)

        infoMsg = "後端 DBMS 操作系統是 %s" % Backend.getOs()

        self.createSupportTbl(self.fileTblName, self.tblField, "varchar(1000)")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "@@VERSION"))

        # 參考:https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions
        # https://en.wikipedia.org/wiki/Windows_NT#Releases
        versions = {
            "NT": ("4.0", (6, 5, 4, 3, 2, 1)),
            "2000": ("5.0", (4, 3, 2, 1)),
            "XP": ("5.1", (3, 2, 1)),
            "2003": ("5.2", (2, 1)),
            "Vista or 2008": ("6.0", (2, 1)),
            "7 or 2008 R2": ("6.1", (1, 0)),
            "8 or 2012": ("6.2", (0,)),
            "8.1 or 2012 R2": ("6.3", (0,)),
            "10 or 11 or 2016 or 2019 or 2022": ("10.0", (0,))
        }

        # 獲取後端 DBMS 的操作系統版本
        for version, data in versions.items():
            query = "EXISTS(SELECT %s FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%Windows NT " + data[0] + "%')"
            result = inject.checkBooleanExpression(query)

            if result:
                Backend.setOsVersion(version)
                infoMsg += " %s" % Backend.getOsVersion()
                break

        if not Backend.getOsVersion():
            Backend.setOsVersion("2003")
            Backend.setOsServicePack(2)

            warnMsg = "無法識別底層操作系統版本,假設為 Windows %s Service Pack %d" % (Backend.getOsVersion(), Backend.getOsServicePack())
            #warnMsg += "system version, assuming it is Windows "
            #warnMsg += "%s Service Pack %d" % (Backend.getOsVersion(), Backend.getOsServicePack())
            logger.warning("警告:%s" % warnMsg)

            self.cleanup(onlyFileTbl=True)

            return

        # 獲取後端 DBMS 的操作系統服務包
        sps = versions[Backend.getOsVersion()][1]
        for sp in sps:
            query = "EXISTS(SELECT %s FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%Service Pack " + getUnicode(sp) + "%')"
            result = inject.checkBooleanExpression(query)

            if result:
                Backend.setOsServicePack(sp)
                break

        if not Backend.getOsServicePack():
            debugMsg = "假設操作系統沒有服務包"
            logger.debug("調試:%s" % debugMsg)

            Backend.setOsServicePack(0)

        if Backend.getOsVersion():
            infoMsg += " 服務包 %d" % Backend.getOsServicePack()

        logger.info(infoMsg)

        self.cleanup(onlyFileTbl=True)
