#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import re
import shlex
import sys

try:
    from optparse import OptionError as ArgumentError
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser
    from optparse import SUPPRESS_HELP as SUPPRESS

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument_group(self, *args, **kwargs):
        return self.add_option_group(OptionGroup(self, *args, **kwargs))

    ArgumentParser.add_argument_group = _add_argument_group

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser
    from argparse import ArgumentError
    from argparse import SUPPRESS

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

from lib.core.common import checkOldOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import dataToStdout
from lib.core.common import expandMnemonics
from lib.core.common import getSafeExString
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.option import _createHomeDirectories
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORED_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory
from thirdparty.six.moves import input as _input

def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()

    # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

    usage = "%s%s [選項]" % ("%s " % os.path.basename(sys.executable) if not IS_WIN else "", "\"%s\"" % _ if " " in _ else _)
    parser = ArgumentParser(usage=usage)

    try:
        parser.add_argument("--hh", dest="advancedHelp", action="store_true",
            help="顯示高級幫助消息並退出")

        parser.add_argument("--version", dest="showVersion", action="store_true",
            help="顯示程序版本號並退出")

        parser.add_argument("-v", dest="verbose", type=int,
            help="詳細級別：0-6（默認 %d）" % defaults.verbose)

        # Target options
        target = parser.add_argument_group("目標", "必須提供至少一個選項來定義目標")

        target.add_argument("-u", "--url", dest="url",
            help="目標 URL（例如 \"http://www.site.com/vuln.php?id=1\"）")

        target.add_argument("-d", dest="direct",
            help="直接數據庫連接的連接字符串")

        target.add_argument("-l", dest="logFile",
            help="從 Burp 或 WebScarab 代理日誌文件中解析目標")

        target.add_argument("-m", dest="bulkFile",
            help="掃描文本文件中指定的多個目標")

        target.add_argument("-r", dest="requestFile",
            help="從文件加載 HTTP 請求")

        target.add_argument("-g", dest="googleDork",
            help="將 Google dork 結果作為目標 URL 處理")

        target.add_argument("-c", dest="configFile",
            help="從配置 INI 文件加載選項")

        # Request options
        request = parser.add_argument_group("請求", "這些選項可用於指定如何連接到目標 URL")

        request.add_argument("-A", "--user-agent", dest="agent",
            help="HTTP User-Agent 標頭值")

        request.add_argument("-H", "--header", dest="header",
            help="額外標頭（例如 \"X-Forwarded-For: 127.0.0.1\"）")

        request.add_argument("--method", dest="method",
            help="強制使用指定的 HTTP 方法（例如 PUT）")

        request.add_argument("--data", dest="data",
            help="通過 POST 發送的數據字符串（例如 \"id=1\"）")

        request.add_argument("--param-del", dest="paramDel",
            help="用於分割參數值的字符（例如 &）")

        request.add_argument("--cookie", dest="cookie",
            help="HTTP Cookie 標頭值（例如 \"PHPSESSID=a8d127e..\"）")

        request.add_argument("--cookie-del", dest="cookieDel",
            help="用於分割 Cookie 值的字符（例如 ;）")

        request.add_argument("--live-cookies", dest="liveCookies",
            help="用於加載最新值的實時 Cookie 文件")

        request.add_argument("--load-cookies", dest="loadCookies",
            help="包含 Netscape/wget 格式的 Cookie 文件")

        request.add_argument("--drop-set-cookie", dest="dropSetCookie", action="store_true",
            help="忽略響應中的 Set-Cookie 標頭")

        request.add_argument("--http2", dest="http2", action="store_true",
            help="使用 HTTP 版本 2（實驗性）")

        request.add_argument("--mobile", dest="mobile", action="store_true",
            help="通過 HTTP User-Agent 標頭模擬智能手機")

        request.add_argument("--random-agent", dest="randomAgent", action="store_true",
            help="使用隨機選擇的 HTTP User-Agent 標頭值")

        request.add_argument("--host", dest="host",
            help="HTTP Host 標頭值")

        request.add_argument("--referer", dest="referer",
            help="HTTP Referer 標頭值")

        request.add_argument("--headers", dest="headers",
            help="額外標頭（例如 \"Accept-Language: fr\\nETag: 123\"）")

        request.add_argument("--auth-type", dest="authType",
            help="HTTP 認證類型（Basic、Digest、Bearer 等）")

        request.add_argument("--auth-cred", dest="authCred",
            help="HTTP 認證憑據（用戶名:密碼）")

        request.add_argument("--auth-file", dest="authFile",
            help="HTTP 認證 PEM 證書/私鑰文件")

        request.add_argument("--abort-code", dest="abortCode",
            help="在出現（有問題的）HTTP 錯誤代碼時中止（例如 401）")

        request.add_argument("--ignore-code", dest="ignoreCode",
            help="忽略（有問題的）HTTP 錯誤代碼（例如 401）")

        request.add_argument("--ignore-proxy", dest="ignoreProxy", action="store_true",
            help="忽略系統默認代理設置")

        request.add_argument("--ignore-redirects", dest="ignoreRedirects", action="store_true",
            help="忽略重定向嘗試")

        request.add_argument("--ignore-timeouts", dest="ignoreTimeouts", action="store_true",
            help="忽略連接超時")

        request.add_argument("--proxy", dest="proxy",
            help="使用代理連接到目標 URL")

        request.add_argument("--proxy-cred", dest="proxyCred",
            help="代理認證憑據（用戶名:密碼）")

        request.add_argument("--proxy-file", dest="proxyFile",
            help="從文件加載代理列表")

        request.add_argument("--proxy-freq", dest="proxyFreq", type=int,
            help="從給定列表中切換代理之間的請求")

        request.add_argument("--tor", dest="tor", action="store_true",
            help="使用 Tor 匿名網絡")

        request.add_argument("--tor-port", dest="torPort",
            help="設置非默認的 Tor 代理端口")

        request.add_argument("--tor-type", dest="torType",
            help="設置 Tor 代理類型（HTTP、SOCKS4 或 SOCKS5（默認））")

        request.add_argument("--check-tor", dest="checkTor", action="store_true",
            help="檢查 Tor 是否正確使用")

        request.add_argument("--delay", dest="delay", type=float,
            help="每個 HTTP 請求之間的延遲（秒）")

        request.add_argument("--timeout", dest="timeout", type=float,
            help="連接超時前的等待秒數（默認 %d）" % defaults.timeout)

        request.add_argument("--retries", dest="retries", type=int,
            help="連接超時時的重試次數（默認 %d）" % defaults.retries)

        request.add_argument("--retry-on", dest="retryOn",
            help="在正則表達式匹配內容時重試請求（例如 \"drop\"）")

        request.add_argument("--randomize", dest="rParam",
            help="隨機更改指定參數的值")

        request.add_argument("--safe-url", dest="safeUrl",
            help="測試期間頻繁訪問的 URL 地址")

        request.add_argument("--safe-post", dest="safePost",
            help="發送到安全 URL 的 POST 數據")

        request.add_argument("--safe-req", dest="safeReqFile",
            help="從文件加載安全的 HTTP 請求")

        request.add_argument("--safe-freq", dest="safeFreq", type=int,
            help="訪問安全 URL 之間的常規請求")

        request.add_argument("--skip-urlencode", dest="skipUrlEncode", action="store_true",
            help="跳過負載數據的 URL 編碼")

        request.add_argument("--csrf-token", dest="csrfToken",
            help="用於保存反 CSRF 令牌的參數")

        request.add_argument("--csrf-url", dest="csrfUrl",
            help="訪問以提取反 CSRF 令牌的 URL 地址")

        request.add_argument("--csrf-method", dest="csrfMethod",
            help="訪問反 CSRF 令牌頁面時使用的 HTTP 方法")

        request.add_argument("--csrf-data", dest="csrfData",
            help="訪問反 CSRF 令牌頁面時發送的 POST 數據")

        request.add_argument("--csrf-retries", dest="csrfRetries", type=int,
            help="反 CSRF 令牌獲取的重試次數（默認 %d）" % defaults.csrfRetries)

        request.add_argument("--force-ssl", dest="forceSSL", action="store_true",
            help="強制使用 SSL/HTTPS")

        request.add_argument("--chunked", dest="chunked", action="store_true",
            help="使用 HTTP 分塊傳輸編碼（POST）請求")

        request.add_argument("--hpp", dest="hpp", action="store_true",
            help="使用 HTTP 參數汙染方法")

        request.add_argument("--eval", dest="evalCode",
            help="在請求前執行提供的 Python 代碼（例如 \"import hashlib;id2=hashlib.md5(id).hexdigest()\"）")

        # Optimization options
        optimization = parser.add_argument_group("優化", "這些選項可用於優化 sqlmap 的性能")

        optimization.add_argument("-o", dest="optimize", action="store_true",
            help="啟用所有優化開關")

        optimization.add_argument("--predict-output", dest="predictOutput", action="store_true",
            help="預測常見查詢輸出")

        optimization.add_argument("--keep-alive", dest="keepAlive", action="store_true",
            help="使用持久 HTTP(s) 連接")

        optimization.add_argument("--null-connection", dest="nullConnection", action="store_true",
            help="在不獲取實際 HTTP 響應體的情況下檢索頁面長度")

        optimization.add_argument("--threads", dest="threads", type=int,
            help="最大併發 HTTP(s) 請求數（默認 %d）" % defaults.threads)

        # Injection options
        injection = parser.add_argument_group("注入", "這些選項可用於指定要測試的參數、提供自定義注入負載和可選的繞過防護腳本")

        injection.add_argument("-p", dest="testParameter",
            help="可測試的參數")

        injection.add_argument("--skip", dest="skip",
            help="跳過對指定參數的測試")

        injection.add_argument("--skip-static", dest="skipStatic", action="store_true",
            help="跳過測試看起來不是動態的參數")

        injection.add_argument("--param-exclude", dest="paramExclude",
            help="用於排除測試參數的正則表達式（例如 \"ses\"）")

        injection.add_argument("--param-filter", dest="paramFilter",
            help="按位置選擇可測試的參數（例如 \"POST\"）")

        injection.add_argument("--dbms", dest="dbms",
            help="強制後端 DBMS 為指定值")

        injection.add_argument("--dbms-cred", dest="dbmsCred",
            help="DBMS 認證憑據（用戶名:密碼）")

        injection.add_argument("--os", dest="os",
            help="強制後端 DBMS 操作系統為指定值")

        injection.add_argument("--invalid-bignum", dest="invalidBignum", action="store_true",
            help="使用大數字使值無效")

        injection.add_argument("--invalid-logical", dest="invalidLogical", action="store_true",
            help="使用邏輯運算使值無效")

        injection.add_argument("--invalid-string", dest="invalidString", action="store_true",
            help="使用隨機字符串使值無效")

        injection.add_argument("--no-cast", dest="noCast", action="store_true",
            help="關閉負載轉換機制")

        injection.add_argument("--no-escape", dest="noEscape", action="store_true",
            help="關閉字符串轉義機制")

        injection.add_argument("--prefix", dest="prefix",
            help="注入負載前綴字符串")

        injection.add_argument("--suffix", dest="suffix",
            help="注入負載後綴字符串")

        injection.add_argument("--tamper", dest="tamper",
            help="使用指定腳本篡改注入數據")

        # Detection options
        detection = parser.add_argument_group("檢測", "這些選項可用於自定義檢測階段")

        detection.add_argument("--level", dest="level", type=int,
            help="執行的測試級別（1-5，默認 %d）" % defaults.level)

        detection.add_argument("--risk", dest="risk", type=int,
            help="執行的測試風險（1-3，默認 %d）" % defaults.risk)

        detection.add_argument("--string", dest="string",
            help="查詢評估為 True 時匹配的字符串")

        detection.add_argument("--not-string", dest="notString",
            help="查詢評估為 False 時匹配的字符串")

        detection.add_argument("--regexp", dest="regexp",
            help="查詢評估為 True 時匹配的正則表達式")

        detection.add_argument("--code", dest="code", type=int,
            help="查詢評估為 True 時匹配的 HTTP 代碼")

        detection.add_argument("--smart", dest="smart", action="store_true",
            help="僅在啟發式檢測為陽性時執行全面測試")

        detection.add_argument("--text-only", dest="textOnly", action="store_true",
            help="僅基於文本內容比較頁面")

        detection.add_argument("--titles", dest="titles", action="store_true",
            help="僅基於標題比較頁面")

        # Techniques options
        techniques = parser.add_argument_group("技術", "這些選項可用於調整特定 SQL 注入技術的測試")

        techniques.add_argument("--technique", dest="technique",
            help="使用的 SQL 注入技術（默認 \"%s\"）" % defaults.technique)

        techniques.add_argument("--time-sec", dest="timeSec", type=int,
            help="延遲 DBMS 響應的秒數（默認 %d）" % defaults.timeSec)

        techniques.add_argument("--disable-stats", dest="disableStats", action="store_true",
            help="Disable the statistical model for detecting the delay")

        techniques.add_argument("--union-cols", dest="uCols",
            help="測試 UNION 查詢 SQL 注入的列範圍")

        techniques.add_argument("--union-char", dest="uChar",
            help="用於暴力破解列數的字符")

        techniques.add_argument("--union-from", dest="uFrom",
            help="在 UNION 查詢 SQL 注入的 FROM 部分中使用的表")

        techniques.add_argument("--union-values", dest="uValues",
            help="用於 UNION 查詢 SQL 注入的列值")

        techniques.add_argument("--dns-domain", dest="dnsDomain",
            help="用於 DNS 外洩攻擊的域名")

        techniques.add_argument("--second-url", dest="secondUrl",
            help="搜索二階響應的結果頁面 URL")

        techniques.add_argument("--second-req", dest="secondReq",
            help="從文件加載二階 HTTP 請求")

        # Fingerprint options
        fingerprint = parser.add_argument_group("指紋")

        fingerprint.add_argument("-f", "--fingerprint", dest="extensiveFp", action="store_true",
            help="執行全面的 DBMS 版本指紋識別")

        # Enumeration options
        enumeration = parser.add_argument_group("枚舉", "這些選項可用於枚舉後端數據庫管理系統的信息、結構和表中包含的數據")

        enumeration.add_argument("-a", "--all", dest="getAll", action="store_true",
            help="檢索所有內容")

        enumeration.add_argument("-b", "--banner", dest="getBanner", action="store_true",
            help="檢索 DBMS 橫幅")

        enumeration.add_argument("--current-user", dest="getCurrentUser", action="store_true",
            help="檢索 DBMS 當前用戶")

        enumeration.add_argument("--current-db", dest="getCurrentDb", action="store_true",
            help="檢索 DBMS 當前數據庫")

        enumeration.add_argument("--hostname", dest="getHostname", action="store_true",
            help="檢索 DBMS 服務器主機名")

        enumeration.add_argument("--is-dba", dest="isDba", action="store_true",
            help="檢測 DBMS 當前用戶是否為 DBA")

        enumeration.add_argument("--users", dest="getUsers", action="store_true",
            help="枚舉 DBMS 用戶")

        enumeration.add_argument("--passwords", dest="getPasswordHashes", action="store_true",
            help="枚舉 DBMS 用戶密碼哈希")

        enumeration.add_argument("--privileges", dest="getPrivileges", action="store_true",
            help="枚舉 DBMS 用戶權限")

        enumeration.add_argument("--roles", dest="getRoles", action="store_true",
            help="枚舉 DBMS 用戶角色")

        enumeration.add_argument("--dbs", dest="getDbs", action="store_true",
            help="枚舉 DBMS 數據庫")

        enumeration.add_argument("--tables", dest="getTables", action="store_true",
            help="枚舉 DBMS 數據庫表")

        enumeration.add_argument("--columns", dest="getColumns", action="store_true",
            help="枚舉 DBMS 數據庫表列")

        enumeration.add_argument("--schema", dest="getSchema", action="store_true",
            help="枚舉 DBMS 模式")

        enumeration.add_argument("--count", dest="getCount", action="store_true",
            help="檢索表的條目數")

        enumeration.add_argument("--dump", dest="dumpTable", action="store_true",
            help="轉儲 DBMS 數據庫表條目")

        enumeration.add_argument("--dump-all", dest="dumpAll", action="store_true",
            help="轉儲所有 DBMS 數據庫表條目")

        enumeration.add_argument("--search", dest="search", action="store_true",
            help="搜索列、表和/或數據庫名稱")

        enumeration.add_argument("--comments", dest="getComments", action="store_true",
            help="在枚舉期間檢查 DBMS 註釋")

        enumeration.add_argument("--statements", dest="getStatements", action="store_true",
            help="檢索在 DBMS 上運行的 SQL 語句")

        enumeration.add_argument("-D", dest="db",
            help="要枚舉的 DBMS 數據庫")

        enumeration.add_argument("-T", dest="tbl",
            help="要枚舉的 DBMS 數據庫表")

        enumeration.add_argument("-C", dest="col",
            help="要枚舉的 DBMS 數據庫表列")

        enumeration.add_argument("-X", dest="exclude",
            help="不枚舉的 DBMS 數據庫標識符")

        enumeration.add_argument("-U", dest="user",
            help="要枚舉的 DBMS 用戶")

        enumeration.add_argument("--exclude-sysdbs", dest="excludeSysDbs", action="store_true",
            help="枚舉表時排除 DBMS 系統數據庫")

        enumeration.add_argument("--pivot-column", dest="pivotColumn",
            help="樞軸列名稱")

        enumeration.add_argument("--where", dest="dumpWhere",
            help="在錶轉儲時使用 WHERE 條件")

        enumeration.add_argument("--start", dest="limitStart", type=int,
            help="要檢索的第一個轉儲表條目")

        enumeration.add_argument("--stop", dest="limitStop", type=int,
            help="要檢索的最後一個轉儲表條目")

        enumeration.add_argument("--first", dest="firstChar", type=int,
            help="要檢索的第一個查詢輸出單詞字符")

        enumeration.add_argument("--last", dest="lastChar", type=int,
            help="要檢索的最後一個查詢輸出單詞字符")

        enumeration.add_argument("--sql-query", dest="sqlQuery",
            help="要執行的 SQL 語句")

        enumeration.add_argument("--sql-shell", dest="sqlShell", action="store_true",
            help="提示進入交互式 SQL shell")

        enumeration.add_argument("--sql-file", dest="sqlFile",
            help="從給定文件執行 SQL 語句")

        # Brute force options
        brute = parser.add_argument_group("暴力破解", "這些選項可用於運行暴力破解檢查")

        brute.add_argument("--common-tables", dest="commonTables", action="store_true",
            help="檢查常見表的存在")

        brute.add_argument("--common-columns", dest="commonColumns", action="store_true",
            help="檢查常見列的存在")

        brute.add_argument("--common-files", dest="commonFiles", action="store_true",
            help="檢查常見文件的存在")

        # User-defined function options
        udf = parser.add_argument_group("用戶定義函數注入", "這些選項可用於創建自定義用戶定義函數")

        udf.add_argument("--udf-inject", dest="udfInject", action="store_true",
            help="注入自定義用戶定義函數")

        udf.add_argument("--shared-lib", dest="shLib",
            help="共享庫的本地路徑")

        # File system options
        filesystem = parser.add_argument_group("文件系統訪問", "這些選項可用於訪問後端數據庫管理系統的底層文件系統")

        filesystem.add_argument("--file-read", dest="fileRead",
            help="從後端 DBMS 文件系統讀取文件")

        filesystem.add_argument("--file-write", dest="fileWrite",
            help="在後端 DBMS 文件系統上寫入本地文件")

        filesystem.add_argument("--file-dest", dest="fileDest",
            help="要寫入的後端 DBMS 絕對文件路徑")

        # Takeover options
        takeover = parser.add_argument_group("操作系統訪問", "這些選項可用於訪問後端數據庫管理系統的底層操作系統")

        takeover.add_argument("--os-cmd", dest="osCmd",
            help="執行操作系統命令")

        takeover.add_argument("--os-shell", dest="osShell", action="store_true",
            help="提示進入交互式操作系統 shell")

        takeover.add_argument("--os-pwn", dest="osPwn", action="store_true",
            help="提示進入 OOB shell、Meterpreter 或 VNC")

        takeover.add_argument("--os-smbrelay", dest="osSmb", action="store_true",
            help="一鍵提示進入 OOB shell、Meterpreter 或 VNC")

        takeover.add_argument("--os-bof", dest="osBof", action="store_true",
            help="存儲過程緩衝區溢出利用")
                                 #"exploitation")

        takeover.add_argument("--priv-esc", dest="privEsc", action="store_true",
            help="數據庫進程用戶權限提升")

        takeover.add_argument("--msf-path", dest="msfPath",
            help="Metasploit Framework 安裝的本地路徑")

        takeover.add_argument("--tmp-path", dest="tmpPath",
            help="臨時文件目錄的遠程絕對路徑")

        # Windows registry options
        windows = parser.add_argument_group("Windows 註冊表訪問", "這些選項可用於訪問後端數據庫管理系統的 Windows 註冊表")

        windows.add_argument("--reg-read", dest="regRead", action="store_true",
            help="讀取 Windows 註冊表鍵值")

        windows.add_argument("--reg-add", dest="regAdd", action="store_true",
            help="寫入 Windows 註冊表鍵值數據")

        windows.add_argument("--reg-del", dest="regDel", action="store_true",
            help="刪除 Windows 註冊表鍵值")

        windows.add_argument("--reg-key", dest="regKey",
            help="Windows 註冊表鍵")

        windows.add_argument("--reg-value", dest="regVal",
            help="Windows 註冊表鍵值")

        windows.add_argument("--reg-data", dest="regData",
            help="Windows 註冊表鍵值數據")

        windows.add_argument("--reg-type", dest="regType",
            help="Windows 註冊表鍵值類型")

        # General options
        general = parser.add_argument_group("常規", "這些選項可用於設置一些常規工作參數")

        general.add_argument("-s", dest="sessionFile",
            help="從存儲的 (.sqlite) 文件加載會話")

        general.add_argument("-t", dest="trafficFile",
            help="將所有 HTTP 流量記錄到文本文件")

        general.add_argument("--abort-on-empty", dest="abortOnEmpty", action="store_true",
            help="在結果為空時中止數據檢索")

        general.add_argument("--answers", dest="answers",
            help="設置預定義答案（例如 \"quit=N,follow=N\"）")

        general.add_argument("--base64", dest="base64Parameter",
            help="包含 Base64 編碼數據的參數")

        general.add_argument("--base64-safe", dest="base64Safe", action="store_true",
            help="使用 URL 和文件名安全的 Base64 字母表（RFC 4648）")

        general.add_argument("--batch", dest="batch", action="store_true",
            help="從不詢問用戶輸入，使用默認行為")

        general.add_argument("--binary-fields", dest="binaryFields",
            help="具有二進制值的結果字段（例如 \"digest\"）")

        general.add_argument("--check-internet", dest="checkInternet", action="store_true",
            help="在評估目標前檢查互聯網連接")

        general.add_argument("--cleanup", dest="cleanup", action="store_true",
            help="從 DBMS 中清理 sqlmap 特定的 UDF 和表")

        general.add_argument("--crawl", dest="crawlDepth", type=int,
            help="從目標 URL 開始爬取網站")

        general.add_argument("--crawl-exclude", dest="crawlExclude",
            help="用於排除爬取頁面的正則表達式（例如 \"logout\"）")

        general.add_argument("--csv-del", dest="csvDel",
            help="CSV 輸出中使用的分隔字符（默認 \"%s\"）" % defaults.csvDel)

        general.add_argument("--charset", dest="charset",
            help="盲注 SQL 注入字符集（例如 \"0123456789abcdef\"）")

        general.add_argument("--dump-file", dest="dumpFile",
            help="將轉儲的數據存儲到自定義文件")

        general.add_argument("--dump-format", dest="dumpFormat",
            help="轉儲數據的格式（CSV（默認）、HTML 或 SQLITE）")

        general.add_argument("--encoding", dest="encoding",
            help="用於數據檢索的字符編碼（例如 GBK）")

        general.add_argument("--eta", dest="eta", action="store_true",
            help="為每個輸出顯示預計到達時間")

        general.add_argument("--flush-session", dest="flushSession", action="store_true",
            help="刷新當前目標的會話文件")

        general.add_argument("--forms", dest="forms", action="store_true",
            help="解析並測試目標 URL 上的表單")

        general.add_argument("--fresh-queries", dest="freshQueries", action="store_true",
            help="忽略存儲在會話文件中的查詢結果")

        general.add_argument("--gpage", dest="googlePage", type=int,
            help="使用指定頁碼的 Google dork 結果")

        general.add_argument("--har", dest="harFile",
            help="將所有 HTTP 流量記錄到 HAR 文件")

        general.add_argument("--hex", dest="hexConvert", action="store_true",
            help="在數據檢索期間使用十六進制轉換")

        general.add_argument("--output-dir", dest="outputDir", action="store",
            help="自定義輸出目錄路徑")

        general.add_argument("--parse-errors", dest="parseErrors", action="store_true",
            help="解析並顯示響應中的 DBMS 錯誤消息")

        general.add_argument("--preprocess", dest="preprocess",
            help="使用指定腳本進行預處理（請求）")

        general.add_argument("--postprocess", dest="postprocess",
            help="使用指定腳本進行後處理（響應）")

        general.add_argument("--repair", dest="repair", action="store_true",
            help="重新轉儲具有未知字符標記的條目（%s）" % INFERENCE_UNKNOWN_CHAR)

        general.add_argument("--save", dest="saveConfig",
            help="將選項保存到配置 INI 文件")

        general.add_argument("--scope", dest="scope",
            help="用於過濾目標的正則表達式")

        general.add_argument("--skip-heuristics", dest="skipHeuristics", action="store_true",
            help="跳過漏洞的啟發式檢測")

        general.add_argument("--skip-waf", dest="skipWaf", action="store_true",
            help="跳過 WAF/IPS 保護的啟發式檢測")

        general.add_argument("--table-prefix", dest="tablePrefix",
            help="臨時表使用的前綴（默認：\"%s\"）" % defaults.tablePrefix)

        general.add_argument("--test-filter", dest="testFilter",
            help="按負載和/或標題選擇測試（例如 ROW）")

        general.add_argument("--test-skip", dest="testSkip",
            help="按負載和/或標題跳過測試（例如 BENCHMARK）")

        general.add_argument("--time-limit", dest="timeLimit", type=float,
            help="以秒為單位的時間限制運行（例如 3600）")

        general.add_argument("--unsafe-naming", dest="unsafeNaming", action="store_true",
            help="禁用 DBMS 標識符的轉義（例如 \"user\"）")

        general.add_argument("--web-root", dest="webRoot",
            help="Web 服務器文檔根目錄（例如 \"/var/www\"）")

        # Miscellaneous options
        miscellaneous = parser.add_argument_group("雜項", "這些選項不屬於任何其他類別")

        miscellaneous.add_argument("-z", dest="mnemonics",
            help="使用短助記符（例如 \"flu,bat,ban,tec=EU\"）")

        miscellaneous.add_argument("--alert", dest="alert",
            help="發現 SQL 注入時運行主機操作系統命令")

        miscellaneous.add_argument("--beep", dest="beep", action="store_true",
            help="在提問和/或發現漏洞時發出蜂鳴聲")

        miscellaneous.add_argument("--dependencies", dest="dependencies", action="store_true",
            help="檢查缺失的（可選）sqlmap 依賴項")

        miscellaneous.add_argument("--disable-coloring", dest="disableColoring", action="store_true",
            help="禁用控制檯輸出著色")

        miscellaneous.add_argument("--disable-hashing", dest="disableHashing", action="store_true",
            help="禁用錶轉儲的哈希分析")

        miscellaneous.add_argument("--list-tampers", dest="listTampers", action="store_true",
            help="顯示可用的繞過防護腳本列表")

        miscellaneous.add_argument("--no-logging", dest="noLogging", action="store_true",
            help="禁用記錄到文件")

        miscellaneous.add_argument("--no-truncate", dest="noTruncate", action="store_true",
            help="禁用控制檯輸出截斷（例如長條目...）")

        miscellaneous.add_argument("--offline", dest="offline", action="store_true",
            help="在離線模式下工作（僅使用會話數據）")

        miscellaneous.add_argument("--purge", dest="purge", action="store_true",
            help="安全刪除 sqlmap 數據目錄中的所有內容")

        miscellaneous.add_argument("--results-file", dest="resultsFile",
            help="多目標模式下 CSV 結果文件的位置")

        miscellaneous.add_argument("--shell", dest="shell", action="store_true",
            help="提示進入交互式 sqlmap shell")

        miscellaneous.add_argument("--tmp-dir", dest="tmpDir",
            help="存儲臨時文件的本地目錄")

        miscellaneous.add_argument("--unstable", dest="unstable", action="store_true",
            help="調整不穩定連接的選項")

        miscellaneous.add_argument("--update", dest="updateAll", action="store_true",
            help="更新 sqlmap")

        miscellaneous.add_argument("--wizard", dest="wizard", action="store_true",
            help="為初學者用戶提供的簡單向導界面")

        # Hidden and/or experimental options
        parser.add_argument("--crack", dest="hashFile",
            help=SUPPRESS)  # "Load and crack hashes from a file (standalone)"

        parser.add_argument("--dummy", dest="dummy", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--yuge", dest="yuge", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--murphy-rate", dest="murphyRate", type=int,
            help=SUPPRESS)

        parser.add_argument("--debug", dest="debug", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--deprecations", dest="deprecations", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-multi", dest="disableMulti", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-precon", dest="disablePrecon", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--profile", dest="profile", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--localhost", dest="localhost", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-dbms", dest="forceDbms",
            help=SUPPRESS)

        parser.add_argument("--force-dns", dest="forceDns", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-partial", dest="forcePartial", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-pivoting", dest="forcePivoting", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--ignore-stdin", dest="ignoreStdin", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--non-interactive", dest="nonInteractive", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--gui", dest="gui", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--smoke-test", dest="smokeTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--vuln-test", dest="vulnTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-json", dest="disableJson", action="store_true",
            help=SUPPRESS)

        # API options
        parser.add_argument("--api", dest="api", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--taskid", dest="taskid",
            help=SUPPRESS)

        parser.add_argument("--database", dest="database",
            help=SUPPRESS)

        # Dirty hack to display longer options without breaking into two lines
        if hasattr(parser, "formatter"):
            def _(self, *args):
                retVal = parser.formatter._format_option_strings(*args)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
                return retVal

            parser.formatter._format_option_strings = parser.formatter.format_option_strings
            parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
        else:
            def _format_action_invocation(self, action):
                retVal = self.__format_action_invocation(action)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - self._indent_increment)) % retVal
                return retVal

            parser.formatter_class.__format_action_invocation = parser.formatter_class._format_action_invocation
            parser.formatter_class._format_action_invocation = _format_action_invocation

        # Dirty hack for making a short option '-hh'
        if hasattr(parser, "get_option"):
            option = parser.get_option("--hh")
            option._short_opts = ["-hh"]
            option._long_opts = []
        else:
            for action in get_actions(parser):
                if action.option_strings == ["--hh"]:
                    action.option_strings = ["-hh"]
                    break

        # Dirty hack for inherent help message of switch '-h'
        if hasattr(parser, "get_option"):
            option = parser.get_option("-h")
            option.help = option.help.capitalize().replace("Show this help message and exit", "顯示此幫助消息並退出")
        else:
            for action in get_actions(parser):
                if action.option_strings == ["-h", "--help"]:
                    action.help = action.help.capitalize().replace("Show this help message and exit", "顯示此幫助消息並退出")
                    break

        _ = []
        advancedHelp = True
        extraHeaders = []
        auxIndexes = {}

        # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.stdin.encoding))

        argv = _
        checkOldOptions(argv)

        if "--gui" in argv:
            from lib.core.gui import runGui

            runGui(parser)

            raise SqlmapSilentQuitException

        elif "--shell" in argv:
            _createHomeDirectories()

            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            commands = set(("x", "q", "exit", "quit", "clear"))
            commands.update(get_all_options(parser))

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=commands)

            while True:
                command = None
                prompt = "sqlmap > "

                try:
                    # Note: in Python2 command should not be converted to Unicode before passing to shlex (Reference: https://bugs.python.org/issue1170)
                    command = _input(prompt).strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    raise SqlmapShellQuitException

                command = re.sub(r"(?i)\Anew\s+", "", command or "")

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    dataToStdout("[i]歷史記錄已清除\n")
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    if not re.search(r"(?i)\A(\?|help)\Z", command):
                        dataToStdout("[!]提供了無效的選項\n")
                    dataToStdout("[i]有效示例：-u http://www.site.com/vuln.php?id=1 --banner'\n")
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError as ex:
                raise SqlmapSyntaxException("命令行解析過程中出現錯誤（'%s'）" % getSafeExString(ex))

        longOptions = set(re.findall(r"\-\-([^= ]+?)=", parser.format_help()))
        longSwitches = set(re.findall(r"\-\-([^= ]+?)\s", parser.format_help()))

        for i in xrange(len(argv)):
            # Reference: https://en.wiktionary.org/wiki/-
            argv[i] = re.sub(u"\\A(\u2010|\u2013|\u2212|\u2014|\u4e00|\u1680|\uFE63|\uFF0D)+", lambda match: '-' * len(match.group(0)), argv[i])

            # Reference: https://unicode-table.com/en/sets/quotation-marks/
            argv[i] = argv[i].strip(u"\u00AB\u2039\u00BB\u203A\u201E\u201C\u201F\u201D\u2019\u275D\u275E\u276E\u276F\u2E42\u301D\u301E\u301F\uFF02\u201A\u2018\u201B\u275B\u275C")

            if argv[i] == "-hh":
                argv[i] = "-h"
            elif i == 1 and re.search(r"\A(http|www\.|\w[\w.-]+\.\w{2,})", argv[i]) is not None:
                argv[i] = "--url=%s" % argv[i]
            elif len(argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((argv[i].split('=', 1)[-1].strip() or ' ')[0], argv[i][-1])):
                dataToStdout("[!] 從網絡複製粘貼非法的（非控制檯）引號字符是無效的 (%s)\n" % argv[i])
                raise SystemExit
            elif len(argv[i]) > 1 and u"\uff0c" in argv[i].split('=', 1)[-1]:
                dataToStdout("[!] 從網絡複製粘貼非法的（非控制檯）逗號字符是無效的 (%s)\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w=.+", argv[i]):
                dataToStdout("[!] 檢測到可能拼寫錯誤的短選項（非法的 '=' 使用）: ('%s')\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w{3,}", argv[i]):
                if argv[i].strip('-').split('=')[0] in (longOptions | longSwitches):
                    argv[i] = "-%s" % argv[i]
            elif argv[i] in IGNORED_OPTIONS:
                argv[i] = ""
            elif argv[i] in DEPRECATED_OPTIONS:
                argv[i] = ""
            elif argv[i] in ("-s", "--silent"):
                if i + 1 < len(argv) and argv[i + 1].startswith('-') or i + 1 == len(argv):
                    argv[i] = ""
                    conf.verbose = 0
            elif argv[i].startswith("--data-raw"):
                argv[i] = argv[i].replace("--data-raw", "--data", 1)
            elif argv[i].startswith("--auth-creds"):
                argv[i] = argv[i].replace("--auth-creds", "--auth-cred", 1)
            elif argv[i].startswith("--drop-cookie"):
                argv[i] = argv[i].replace("--drop-cookie", "--drop-set-cookie", 1)
            elif re.search(r"\A--tamper[^=\s]", argv[i]):
                argv[i] = ""
            elif re.search(r"\A(--(tamper|ignore-code|skip))(?!-)", argv[i]):
                key = re.search(r"\-?\-(\w+)\b", argv[i]).group(1)
                index = auxIndexes.get(key, None)
                if index is None:
                    index = i if '=' in argv[i] else (i + 1 if i + 1 < len(argv) and not argv[i + 1].startswith('-') else None)
                    auxIndexes[key] = index
                else:
                    delimiter = ','
                    argv[index] = "%s%s%s" % (argv[index], delimiter, argv[i].split('=')[1] if '=' in argv[i] else (argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith('-') else ""))
                    argv[i] = ""
            elif argv[i] in ("-H", "--header") or any(argv[i].startswith("%s=" % _) for _ in ("-H", "--header")):
                if '=' in argv[i]:
                    extraHeaders.append(argv[i].split('=', 1)[1])
                elif i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif argv[i] == "--deps":
                argv[i] = "--dependencies"
            elif argv[i] == "--disable-colouring":
                argv[i] = "--disable-coloring"
            elif argv[i] == "-r":
                for j in xrange(i + 2, len(argv)):
                    value = argv[j]
                    if os.path.isfile(value):
                        argv[i + 1] += ",%s" % value
                        argv[j] = ''
                    else:
                        break
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print(VERSION_STRING.split('/')[-1])
                raise SystemExit
            elif argv[i] in ("-h", "--help"):
                advancedHelp = False
                for group in get_groups(parser)[:]:
                    found = False
                    for option in get_actions(group):
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS
                        else:
                            found = True
                    if not found:
                        get_groups(parser).remove(group)
            elif '=' in argv[i] and not argv[i].startswith('-') and argv[i].split('=')[0] in longOptions and re.search(r"\A-{1,2}\w", argv[i - 1]) is None:
                dataToStdout("[!] 檢測到使用了未加前導連字符的長選項： ('%s')\n" % argv[i])
                raise SystemExit

        for verbosity in (_ for _ in argv if re.search(r"\A\-v+\Z", _)):
            try:
                if argv.index(verbosity) == len(argv) - 1 or not argv[argv.index(verbosity) + 1].isdigit():
                    conf.verbose = verbosity.count('v')
                    del argv[argv.index(verbosity)]
            except (IndexError, ValueError):
                pass

        try:
            (args, _) = parser.parse_known_args(argv) if hasattr(parser, "parse_known_args") else parser.parse_args(argv)
        except UnicodeEncodeError as ex:
            dataToStdout("\n[!] %s\n" % getUnicode(ex.object.encode("unicode-escape")))
            raise SystemExit
        except SystemExit:
            if "-h" in argv and not advancedHelp:
                dataToStdout("\n[!] 查看選項的完整列表 '-hh'\n")
            raise

        if extraHeaders:
            if not args.headers:
                args.headers = ""
            delimiter = "\\n" if "\\n" in args.headers else "\n"
            args.headers += delimiter + delimiter.join(extraHeaders)

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(argv) - 1):
            if argv[i] == "-z":
                expandMnemonics(argv[i + 1], parser, args)

        if args.dummy:
            args.url = args.url or DUMMY_URL

        if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), args.api, args.ignoreStdin, "GITHUB_ACTIONS" in os.environ)):
            args.stdinPipe = iter(sys.stdin.readline, None)
        else:
            args.stdinPipe = None

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, args.requestFile, args.updateAll, args.smokeTest, args.vulnTest, args.wizard, args.dependencies, args.purge, args.listTampers, args.hashFile, args.stdinPipe)):
            errMsg = "缺少強制選項 (-d, -u, -l, -m, -r, -g, -c, --wizard, --shell, --update, --purge, --list-tampers or --dependencies). "
            errMsg += "使用 -h 表示基本幫助,使用 -hh 表示高級幫助\n"
            parser.error(errMsg)

        return args

    except (ArgumentError, TypeError) as ex:
        parser.error(ex)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN and "--non-interactive" not in sys.argv:
            dataToStdout("\n 按 Enter 鍵繼續...")
            _input()
        raise

    debugMsg = "解析命令行參數"
    logger.debug(debugMsg)
