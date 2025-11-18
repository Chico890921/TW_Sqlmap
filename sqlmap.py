#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

try:
    import sys

    sys.dont_write_bytecode = True

    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError:
        sys.exit("[!] 檢測到安裝異常（缺少模塊）。請訪問：https://github.com/sqlmapproject/sqlmap/#installation 獲取更多信息。")

    import bdb
    import glob
    import inspect
    import json
    import logging
    import os
    import re
    import shutil
    import sys
    import tempfile
    import threading
    import time
    import traceback
    import warnings

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    else:
        warnings.resetwarnings()
        warnings.filterwarnings(action="ignore", message="'crypt'", category=DeprecationWarning)
        warnings.simplefilter("ignore", category=ImportWarning)
        if sys.version_info >= (3, 0):
            warnings.simplefilter("ignore", category=ResourceWarning)

    warnings.filterwarnings(action="ignore", message="Python 2 不再受支持")
    warnings.filterwarnings(action="ignore", message=".*已經被導入", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*使用了非常舊的版本", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*將使用默認緩衝區大小", category=RuntimeWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")

    from lib.core.data import logger

    from lib.core.common import banner
    from lib.core.common import checkPipedInput
    from lib.core.common import checkSums
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import extractRegexResult
    from lib.core.common import filterNone
    from lib.core.common import getDaysFromLastUpdate
    from lib.core.common import getFileItems
    from lib.core.common import getSafeExString
    from lib.core.common import maskSensitiveData
    from lib.core.common import openFile
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.convert import getUnicode
    from lib.core.common import setColor
    from lib.core.common import unhandledExceptionMessage
    from lib.core.compat import LooseVersion
    from lib.core.compat import xrange
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.datatype import OrderedSet
    from lib.core.enums import MKSTEMP_PREFIX
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import init
    from lib.core.option import initOptions
    from lib.core.patch import dirtyPatches
    from lib.core.patch import resolveCrossReferences
    from lib.core.settings import GIT_PAGE
    from lib.core.settings import IS_WIN
    from lib.core.settings import LAST_UPDATE_NAGGING_DAYS
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import VERSION
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl
except KeyboardInterrupt:
    errMsg = "用戶中止"

    if "logger" in globals():
        logger.critical(errMsg)
        raise SystemExit
    else:
        import time
        sys.exit("\r[%s] [嚴重] %s" % (time.strftime("%X"), errMsg))

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try:
        os.path.isdir(modulePath())
    except UnicodeEncodeError:
        errMsg = "您的系統無法正確處理非 ASCII 路徑。"
        errMsg += "請將 sqlmap 的目錄移動到其他位置"
        logger.critical(errMsg)
        raise SystemExit

    if LooseVersion(VERSION) < LooseVersion("1.0"):
        errMsg = "您的運行環境 (例如 PYTHONPATH) 已損壞。請確保您沒有使用較舊版本的運行時腳本運行更新的 sqlmap 版本"
        #errMsg += "broken. Please make sure that you are not running "
        #errMsg += "newer versions of sqlmap with runtime scripts for older "
        #errMsg += "versions"
        logger.critical(errMsg)
        raise SystemExit

    # Patch for pip (import) environment
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)

        for _ in ("SqlmapBaseException", "SqlmapShellQuitException", "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)

def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        dirtyPatches()
        resolveCrossReferences()
        checkEnvironment()
        setPaths(modulePath())
        banner()

        # Store original command line options for possible later restoration
        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)

        if checkPipedInput():
            conf.batch = True

        if conf.get("api"):
            # heavy imports
            from lib.utils.api import StdDbOut
            from lib.utils.api import setRestAPILog

            # Overwrite system standard output and standard error to write
            # to an IPC database
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")

            setRestAPILog()

        conf.showTime = True
        dataToStdout("[!] 法律聲明:%s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] 開始 %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        init()

        if not conf.updateAll:
            # Postponed imports (faster start)
            if conf.smokeTest:
                from lib.core.testing import smokeTest
                os._exitcode = 1 - (smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest
                os._exitcode = 1 - (vulnTest() or 0)
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile
                    globals()["start"] = start
                    profile()
                else:
                    try:
                        if conf.crawlDepth and conf.bulkFile:
                            targets = getFileItems(conf.bulkFile)

                            for i in xrange(len(targets)):
                                target = None

                                try:
                                    kb.targets = OrderedSet()
                                    target = targets[i]

                                    if not re.search(r"(?i)\Ahttp[s]*://", target):
                                        target = "http://%s" % target

                                    infoMsg = "開始爬取目標 URL '%s'(%d/%d)" % (target, i + 1, len(targets))
                                    logger.info(infoMsg)

                                    crawl(target)
                                except Exception as ex:
                                    if target and not isinstance(ex, SqlmapUserQuitException):
                                        errMsg = "在爬取 '%s' 時出現問題 ('%s)" % (target, getSafeExString(ex))
                                        logger.error(errMsg)
                                    else:
                                        raise
                                else:
                                    if kb.targets:
                                        start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1

                        if "can't start new thread" in getSafeExString(ex):
                            errMsg = "無法啟動新線程。請檢查操作系統的限制"
                            logger.critical(errMsg)
                            raise SystemExit
                        else:
                            raise

    except SqlmapUserQuitException:
        if not conf.batch:
            errMsg = "用戶退出"
            logger.error(errMsg)

    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass

    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False

    except SqlmapBaseException as ex:
        errMsg = getSafeExString(ex)
        logger.critical(errMsg)

        os._exitcode = 1

        raise SystemExit

    except KeyboardInterrupt:
        try:
            print()
        except IOError:
            pass

    except EOFError:
        print()

        errMsg = "退出"
        logger.error(errMsg)

    except SystemExit as ex:
        os._exitcode = ex.code or 0

    except:
        print()
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        valid = checkSums()

        os._exitcode = 255

        if any(_ in excMsg for _ in ("MemoryError", "Cannot allocate memory")):
            errMsg = "檢測到內存耗盡"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("No space left", "Disk quota exceeded", "Disk full while accessing")):
            errMsg = "輸出設備上沒有剩餘空間"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("The paging file is too small",)):
            errMsg = "分頁文件的空間不足"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Access is denied", "subprocess", "metasploit")):
            errMsg = "運行 Metasploit 時發生權限錯誤"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Permission denied", "metasploit")):
            errMsg = "使用 Metasploit 時發生權限錯誤"
            logger.critical(errMsg)
            raise SystemExit

        elif "Read-only file system" in excMsg:
            errMsg = "輸出設備已以只讀方式掛載"
            logger.critical(errMsg)
            raise SystemExit

        elif "Insufficient system resources" in excMsg:
            errMsg = "檢測到資源耗盡"
            logger.critical(errMsg)
            raise SystemExit

        elif "OperationalError: disk I/O error" in excMsg:
            errMsg = "輸出設備的 I/O 錯誤"
            logger.critical(errMsg)
            raise SystemExit

        elif "Violation of BIDI" in excMsg:
            errMsg = "無效的 URL(違反 Bidi IDNA 規則 - RFC 5893)"
            logger.critical(errMsg)
            raise SystemExit

        elif "Invalid IPv6 URL" in excMsg:
            errMsg = "無效的 URL('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif "_mkstemp_inner" in excMsg:
            errMsg = "訪問臨時文件時出現問題"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("tempfile.mkdtemp", "tempfile.mkstemp", "tempfile.py")):
            errMsg = "無法寫入臨時目錄 '%s'。" % tempfile.gettempdir()
            errMsg += "請確保您的磁盤未滿,並且您具有足夠的寫入權限來創建臨時文件和/或目錄"
            #errMsg += "that you have sufficient write permissions to "
            #errMsg += "create temporary files and/or directories"
            logger.critical(errMsg)
            raise SystemExit

        elif "Permission denied: '" in excMsg:
            match = re.search(r"Permission denied: '([^']*)", excMsg)
            errMsg = "在訪問文件 '%s' 時發生權限錯誤" % match.group(1)
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("twophase", "sqlalchemy")):
            errMsg = "請更新 'sqlalchemy' 包 (>= 1.1.11)"
            errMsg += "(參考:'https://qiita.com/tkprof/items/7d7b2d00df9c5f16fffe')"
            logger.critical(errMsg)
            raise SystemExit

        elif "invalid maximum character passed to PyUnicode_New" in excMsg and re.search(r"\A3\.[34]", sys.version) is not None:
            errMsg = "請升級 Python 版本 (>= 3.5)"
            errMsg += "(參考:'https://bugs.python.org/issue18183')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("scramble_caching_sha2", "TypeError")):
            errMsg = "請降級 'PyMySQL' 包 (=< 0.8.1)"
            errMsg += "(參考:'https://github.com/PyMySQL/PyMySQL/issues/700')"
            logger.critical(errMsg)
            raise SystemExit

        elif "must be pinned buffer, not bytearray" in excMsg:
            errMsg = "發生了 Python 解釋器中的錯誤,該錯誤已在 2.7.3 版本中修復。請相應地進行更新"
            #errMsg += "is fixed in 2.7. Please update accordingly "
            errMsg += "(參考:'https://bugs.python.org/issue8104')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("OSError: [Errno 22] Invalid argument: '", "importlib")):
            errMsg = "無法讀取文件 '%s'" % extractRegexResult(r"OSError: \[Errno 22\] Invalid argument: '(?P<result>[^']+)", excMsg)
            logger.critical(errMsg)
            raise SystemExit

        elif "hash_randomization" in excMsg:
            errMsg = "發生了 Python 解釋器中的錯誤,該錯誤已在 2.7.3 版本中修復。請相應地進行更新"
            #errMsg += "is fixed in 2.7.3. Please update accordingly "
            errMsg += "(參考:'https://docs.python.org/2/library/sys.html')"
            logger.critical(errMsg)
            raise SystemExit

        elif "AttributeError:" in excMsg and re.search(r"3\.11\.\d+a", sys.version):
            errMsg = "檢測到 SQLMap 在 Python 3.11 的 ALPHA 測試版本上運行存在已知問題"
            errMsg += "，請使用穩定版 Python 以確保正常運行。"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Resource temporarily unavailable", "os.fork()", "dictionaryAttack")):
            errMsg = "在運行多進程哈希破解時出現問題。"
            errMsg += "請使用選項 '--threads=1' 重新運行"
            logger.critical(errMsg)
            raise SystemExit

        elif "can't start new thread" in excMsg:
            errMsg = "在創建新線程實例時出現問題。"
            errMsg += "請確保您沒有運行過多的進程"
            if not IS_WIN:
                errMsg += "(或增加 'ulimit -u' 的值)"
            logger.critical(errMsg)
            raise SystemExit

        elif "can't allocate read lock" in excMsg:
            errMsg = "在常規套接字操作中出現問題"
            errMsg += "('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("pymysql", "configparser")):
            errMsg = "檢測到 'pymsql' 的錯誤初始化 (使用 Python3 的依賴項)"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("ntlm", "socket.error, err", "SyntaxError")):
            errMsg = "檢測到 'python-ntlm' 的錯誤初始化 (使用 Python2 的語法)"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("drda", "to_bytes")):
            errMsg = "檢測到 'drda' 的錯誤初始化 (使用 Python3 的語法)"
            logger.critical(errMsg)
            raise SystemExit

        elif "'WebSocket' object has no attribute 'status'" in excMsg:
            errMsg = "檢測到錯誤的 WebSocket 庫"
            errMsg += "(參考:'https://github.com/sqlmapproject/sqlmap/issues/4572#issuecomment-775041086')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("window = tkinter.Tk()",)):
            errMsg = "在初始化 GUI 界面時出現問題"
            errMsg += "('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("unable to access item 'liveTest'",)):
            errMsg = "檢測到使用不同版本的 sqlmap 文件"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in errMsg for _ in (": 9.9.9#",)):
            errMsg = "出現彩蛋級錯誤：LOL xD)"
            logger.critical(errMsg)
            raise SystemExit

        elif kb.get("dumpKeyboardInterrupt"):
            raise SystemExit

        elif any(_ in excMsg for _ in ("Broken pipe",)):
            raise SystemExit

        elif valid is False:
            errMsg = "代碼完整性檢查失敗 (關閉自動問題創建)。"
            errMsg += "您應該從官方 GitHub 存儲庫中檢索最新的開發版本,地址為 '%s'" % GIT_PAGE
            #errMsg += "repository at '%s'" % GIT_PAGE
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in "%s\n%s" % (errMsg, excMsg) for _ in ("tamper/", "waf/", "--engagement-dojo")):
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("ImportError", "ModuleNotFoundError", "<frozen", "Can't find file for module", "SAXReaderNotAvailable", "<built-in function compile> returned NULL without setting an exception", "source code string cannot contain null bytes", "No module named", "tp_name field", "module 'sqlite3' has no attribute 'OperationalError'")):
            errMsg = "無效的運行環境 ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("SyntaxError: Non-ASCII character", ".py on line", "but no encoding declared")):
            errMsg = "無效的運行環境 ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("FileNotFoundError: [Errno 2] No such file or directory", "cwd = os.getcwd()")):
            errMsg = "無效的運行環境 ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("PermissionError: [WinError 5]", "multiprocessing")):
            errMsg = "在此係統上運行多進程時存在權限問題。"
            errMsg += "請使用 '--disable-multi' 選項重新運行"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("No such file", "_'")):
            errMsg = "檢測到損壞的安裝 ('%s')。" % excMsg.strip().split('\n')[-1]
            errMsg += "您應該從官方 GitHub 存儲庫中檢索最新的開發版本,地址為 '%s'" % GIT_PAGE
            #errMsg += "repository at '%s'" % GIT_PAGE
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("No such file", "sqlmap.conf", "Test")):
            errMsg = "您正在嘗試在生產環境中運行 (隱藏的) 開發測試"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("HTTPNtlmAuthHandler", "'str' object has no attribute 'decode'")):
            errMsg = "包 'python-ntlm' 與 Python 3 存在已知的兼容性問題"
            errMsg += "(參考:'https://github.com/mullender/python-ntlm/pull/61')"
            logger.critical(errMsg)
            raise SystemExit

        elif "'DictObject' object has no attribute '" in excMsg and all(_ in errMsg for _ in ("(fingerprinted)", "(identified)")):
            errMsg = "在枚舉過程中出現問題。"
            errMsg += "由於存在較大的誤報機率,建議您使用選項 '--flush-session' 重新運行"
            #errMsg += "you are advised to rerun with switch '--flush-session'"
            logger.critical(errMsg)
            raise SystemExit

        elif "database disk image is malformed" in excMsg:
            errMsg = "本地會話文件似乎損壞。請使用 '--flush-session' 重新運行"
            logger.critical(errMsg)
            raise SystemExit

        elif "'cryptography' package is required" in excMsg:
            errMsg = "third-party library 'cryptography' is required"
            logger.critical(errMsg)
            raise SystemExit

        elif "AttributeError: 'module' object has no attribute 'F_GETFD'" in excMsg:
            errMsg = "無效的運行環境 (\"%s\")" % excMsg.split("Error: ")[-1].strip()
            errMsg += "(參考:'https://stackoverflow.com/a/38841364' 和 'https://bugs.python.org/issue24944#msg249231')"
            logger.critical(errMsg)
            raise SystemExit

        elif "bad marshal data (unknown type code)" in excMsg:
            match = re.search(r"\s*(.+)\s+ValueError", excMsg)
            errMsg = "您的 .pyc 文件之一損壞%s" % ("('%s')" % match.group(1) if match else "")
            errMsg += "。請刪除系統上的 .pyc 文件以解決問題"
            logger.critical(errMsg)
            raise SystemExit

        for match in re.finditer(r'File "(.+?)", line', excMsg):
            file_ = match.group(1)
            try:
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
            except ValueError:
                pass
            file_ = file_.replace("\\", '/')
            if "../" in file_:
                file_ = re.sub(r"(\.\./)+", '/', file_)
            else:
                file_ = file_.lstrip('/')
            file_ = re.sub(r"/{2,}", '/', file_)
            excMsg = excMsg.replace(match.group(1), file_)

        errMsg = maskSensitiveData(errMsg)
        excMsg = maskSensitiveData(excMsg)

        if conf.get("api") or not valid or kb.get("lastCtrlCTime"):
            logger.critical("%s\n%s" % (errMsg, excMsg))
        else:
            logger.critical(errMsg)
            dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
            createGithubIssue(errMsg, excMsg)

    finally:
        kb.threadContinue = False

        if (getDaysFromLastUpdate() or 0) > LAST_UPDATE_NAGGING_DAYS:
            warnMsg = "您的 sqlmap 版本已過時"
            logger.warning(warnMsg)

        if conf.get("showTime"):
            dataToStdout("\n[*] 結束 @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        kb.threadException = True

        for tempDir in conf.get("tempDirs", []):
            for prefix in (MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING, MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for filepath in glob.glob(os.path.join(tempDir, "%s*" % prefix)):
                    try:
                        os.remove(filepath)
                    except OSError:
                        pass

            if any((conf.vulnTest, conf.smokeTest)) or not filterNone(filepath for filepath in glob.glob(os.path.join(tempDir, '*')) if not any(filepath.endswith(_) for _ in (".lock", ".exe", ".so", '_'))):  # ignore junk files
                try:
                    shutil.rmtree(tempDir, ignore_errors=True)
                except OSError:
                    pass

        if conf.get("hashDB"):
            conf.hashDB.flush(True)
            conf.hashDB.close()         # NOTE: because of PyPy

        if conf.get("harFile"):
            try:
                with openFile(conf.harFile, "w+b") as f:
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(',', ': '))
            except SqlmapBaseException as ex:
                errMsg = getSafeExString(ex)
                logger.critical(errMsg)

        if conf.get("api"):
            conf.databaseCursor.disconnect()

        if conf.get("dumper"):
            conf.dumper.flush()

        # short delay for thread finalization
        _ = time.time()
        while threading.active_count() > 1 and (time.time() - _) > THREAD_FINALIZATION_TIMEOUT:
            time.sleep(0.01)

        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear()
            conf.clear()
            kb.clear()
            conf.disableBanner = True
            main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except:
        traceback.print_exc()
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.active_count() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
else:
    # cancelling postponed imports (because of CI/CD checks)
    __import__("lib.controller.controller")
