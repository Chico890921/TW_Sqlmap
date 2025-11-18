#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import codecs
import functools
import glob
import inspect
import json
import logging
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import traceback

from lib.controller.checks import checkConnection
from lib.core.common import Backend
from lib.core.common import boldifyMessage
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import decodeStringEscape
from lib.core.common import fetchRandomAgent
from lib.core.common import filterNone
from lib.core.common import findLocalPort
from lib.core.common import findPageForms
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import getFileType
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import intersect
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import openFile
from lib.core.common import parseRequestFile
from lib.core.common import parseTargetDirect
from lib.core.common import paths
from lib.core.common import randomStr
from lib.core.common import readCachedFileContent
from lib.core.common import readInput
from lib.core.common import resetCookieJar
from lib.core.common import runningAsAdmin
from lib.core.common import safeExpandUser
from lib.core.common import safeFilepathEncode
from lib.core.common import saveConfig
from lib.core.common import setColor
from lib.core.common import setOptimize
from lib.core.common import setPaths
from lib.core.common import singleTimeWarnMessage
from lib.core.common import urldecode
from lib.core.compat import cmp
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import mergedOptions
from lib.core.data import queries
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.datatype import OrderedSet
from lib.core.defaults import defaults
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import AUTH_TYPE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import DUMP_FORMAT
from lib.core.enums import FORK
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import MOBILES
from lib.core.enums import OPTION_TYPE
from lib.core.enums import PAYLOAD
from lib.core.enums import PRIORITY
from lib.core.enums import PROXY_TYPE
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import WIZARD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.log import FORMATTER
from lib.core.optiondict import optDict
from lib.core.settings import CODECS_LIST_PAGE
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_ALIASES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import DEFAULT_TOR_HTTP_PORTS
from lib.core.settings import DEFAULT_TOR_SOCKS_PORTS
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORE_CODE_WILDCARD
from lib.core.settings import IS_WIN
from lib.core.settings import KB_CHARS_BOUNDARY_CHAR
from lib.core.settings import KB_CHARS_LOW_FREQUENCY_ALPHABET
from lib.core.settings import LOCALHOST
from lib.core.settings import MAX_CONNECT_RETRIES
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_SPLITTING_REGEX
from lib.core.settings import PRECONNECT_CANDIDATE_TIMEOUT
from lib.core.settings import PROXY_ENVIRONMENT_VARIABLES
from lib.core.settings import SOCKET_PRE_CONNECT_QUEUE_SIZE
from lib.core.settings import SQLMAP_ENVIRONMENT_PREFIX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import SUPPORTED_OS
from lib.core.settings import TIME_DELAY_CANDIDATES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.threads import getCurrentThreadData
from lib.core.threads import setDaemon
from lib.core.update import update
from lib.parse.configfile import configFileParser
from lib.parse.payloads import loadBoundaries
from lib.parse.payloads import loadPayloads
from lib.request.basic import checkCharEncoding
from lib.request.basicauthhandler import SmartHTTPBasicAuthHandler
from lib.request.chunkedhandler import ChunkedHandler
from lib.request.connect import Connect as Request
from lib.request.dns import DNSServer
from lib.request.httpshandler import HTTPSHandler
from lib.request.pkihandler import HTTPSPKIAuthHandler
from lib.request.rangehandler import HTTPRangeHandler
from lib.request.redirecthandler import SmartRedirectHandler
from lib.utils.crawler import crawl
from lib.utils.deps import checkDependencies
from lib.utils.har import HTTPCollectorFactory
from lib.utils.purge import purge
from lib.utils.search import search
from thirdparty import six
from thirdparty.keepalive import keepalive
from thirdparty.multipart import multipartpost
from thirdparty.six.moves import collections_abc as _collections
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import http_cookiejar as _http_cookiejar
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks import socks
from xml.etree.ElementTree import ElementTree

authHandler = _urllib.request.BaseHandler()
chunkedHandler = ChunkedHandler()
httpsHandler = HTTPSHandler()
keepAliveHandler = keepalive.HTTPHandler()
proxyHandler = _urllib.request.ProxyHandler()
redirectHandler = SmartRedirectHandler()
rangeHandler = HTTPRangeHandler()
multipartPostHandler = multipartpost.MultipartPostHandler()

# Reference: https://mail.python.org/pipermail/python-list/2009-November/558615.html
try:
    WindowsError
except NameError:
    WindowsError = None

def _loadQueries():
    """
    Loads queries from 'xml/queries.xml' file.
    """

    def iterate(node, retVal=None):
        class DictObject(object):
            def __init__(self):
                self.__dict__ = {}

            def __contains__(self, name):
                return name in self.__dict__

        if retVal is None:
            retVal = DictObject()

        for child in node.findall("*"):
            instance = DictObject()
            retVal.__dict__[child.tag] = instance
            if child.attrib:
                instance.__dict__.update(child.attrib)
            else:
                iterate(child, instance)

        return retVal

    tree = ElementTree()
    try:
        tree.parse(paths.QUERIES_XML)
    except Exception as ex:
        errMsg = "文件 '%s'('%s') 似乎有問題。請確保你沒有對其進行任何更改" % (paths.QUERIES_XML, getSafeExString(ex))
        #errMsg += "the file '%s' ('%s'). Please make " % (paths.QUERIES_XML, getSafeExString(ex))
        #errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException(errMsg)

    for node in tree.findall("*"):
        queries[node.attrib['value']] = iterate(node)

def _setMultipleTargets():
    """
    Define a configuration parameter if we are running in multiple target
    mode.
    """

    initialTargetsCount = len(kb.targets)
    seen = set()

    if not conf.logFile:
        return

    debugMsg = "從 '%s' 解析目標列表" % conf.logFile
    logger.debug(debugMsg)

    if not os.path.exists(conf.logFile):
        errMsg = "指定的目標列表不存在"
        raise SqlmapFilePathException(errMsg)

    if checkFile(conf.logFile, False):
        for target in parseRequestFile(conf.logFile):
            url, _, data, _, _ = target
            key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
            if key not in seen:
                kb.targets.add(target)
                seen.add(key)

    elif os.path.isdir(conf.logFile):
        files = os.listdir(conf.logFile)
        files.sort()

        for reqFile in files:
            if not re.search(r"([\d]+)\-request", reqFile):
                continue

            for target in parseRequestFile(os.path.join(conf.logFile, reqFile)):
                url, _, data, _, _ = target
                key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
                if key not in seen:
                    kb.targets.add(target)
                    seen.add(key)

    else:
        errMsg = "指定的目標列表既不是文件也不是目錄"
        #errMsg += "nor a directory"
        raise SqlmapFilePathException(errMsg)

    updatedTargetsCount = len(kb.targets)

    if updatedTargetsCount > initialTargetsCount:
        infoMsg = "sqlmap 從目標列表中解析出 %d 個 (參數唯一) 請求,準備進行測試" % (updatedTargetsCount - initialTargetsCount)
        #infoMsg += "(parameter unique) requests from the "
        #infoMsg += "targets list ready to be tested"
        logger.info(infoMsg)

def _adjustLoggingFormatter():
    """
    Solves problem of line deletition caused by overlapping logging messages
    and retrieved data info in inference mode
    """

    if hasattr(FORMATTER, '_format'):
        return

    def format(record):
        message = FORMATTER._format(record)
        message = boldifyMessage(message)
        if kb.get("prependFlag"):
            message = "\n%s" % message
            kb.prependFlag = False
        return message

    FORMATTER._format = FORMATTER.format
    FORMATTER.format = format

def _setRequestFromFile():
    """
    This function checks if the way to make a HTTP request is through supplied
    textual file, parses it and saves the information into the knowledge base.
    """

    if conf.requestFile:
        for requestFile in re.split(PARAMETER_SPLITTING_REGEX, conf.requestFile):
            requestFile = safeExpandUser(requestFile)
            url = None
            seen = set()

            if not checkFile(requestFile, False):
                errMsg = "指定的 HTTP 請求文件 '%s' 不存在" % requestFile
                #errMsg += "does not exist"
                raise SqlmapFilePathException(errMsg)

            infoMsg = "解析來自 '%s' 的 HTTP 請求" % requestFile
            logger.info(infoMsg)

            for target in parseRequestFile(requestFile):
                url = target[0]
                if url not in seen:
                    kb.targets.add(target)
                    if len(kb.targets) > 1:
                        conf.multipleTargets = True
                    seen.add(url)

            if url is None:
                errMsg = "指定的文件 '%s' 不包含可用的 HTTP 請求 (帶有參數)" % requestFile
                #errMsg += "does not contain a usable HTTP request (with parameters)"
                raise SqlmapDataException(errMsg)

    if conf.secondReq:
        conf.secondReq = safeExpandUser(conf.secondReq)

        if not checkFile(conf.secondReq, False):
            #errMsg = "specified second-order HTTP request file '%s' " % conf.secondReq
            #errMsg += "does not exist"
            raise SqlmapFilePathException(errMsg)

        infoMsg = "解析來自 '%s' 的二次 HTTP 請求" % conf.secondReq
        logger.info(infoMsg)

        try:
            target = next(parseRequestFile(conf.secondReq, False))
            kb.secondReq = target
        except StopIteration:
            #errMsg = "specified second-order HTTP request file '%s' " % conf.secondReq
            errMsg = "指定的二次 HTTP 請求文件 '%s' 不包含有效的 HTTP 請求" % conf.secondReq
            raise SqlmapDataException(errMsg)

def _setCrawler():
    if not conf.crawlDepth:
        return

    if not conf.bulkFile:
        if conf.url:
            crawl(conf.url)
        elif conf.requestFile and kb.targets:
            target = next(iter(kb.targets))
            crawl(target[0], target[2], target[3])

def _doSearch():
    """
    This function performs search dorking, parses results
    and saves the testable hosts into the knowledge base.
    """

    if not conf.googleDork:
        return

    kb.data.onlyGETs = None

    def retrieve():
        links = search(conf.googleDork)

        if not links:
            errMsg = "無法找到與你的搜索 dork 表達式匹配的結果"
            #errMsg += "search dork expression"
            raise SqlmapGenericException(errMsg)

        for link in links:
            link = urldecode(link)
            if re.search(r"(.*?)\?(.+)", link) or conf.forms:
                kb.targets.add((link, conf.method, conf.data, conf.cookie, None))
            elif re.search(URI_INJECTABLE_REGEX, link, re.I):
                if kb.data.onlyGETs is None and conf.data is None and not conf.googleDork:
                    message = "你想要僅掃描包含 GET 參數的結果嗎？[Y/n] "
                    kb.data.onlyGETs = readInput(message, default='Y', boolean=True)
                if not kb.data.onlyGETs or conf.googleDork:
                    kb.targets.add((link, conf.method, conf.data, conf.cookie, None))

        return links

    while True:
        links = retrieve()

        if kb.targets:
            infoMsg = "找到 %d 個與你的搜索 dork 表達式匹配的結果" % len(links)
            #infoMsg += "search dork expression"

            if not conf.forms:
                infoMsg += ", "

                if len(links) == len(kb.targets):
                    infoMsg += "全部 "
                else:
                    infoMsg += "%d " % len(kb.targets)

                infoMsg += "所有的目標都可以進行測試"

            logger.info(infoMsg)
            break

        else:
            message = "找到 %d 個與你的搜索 dork 表達式匹配的結果,但其中沒有一個具有用於 SQL 注入測試的 GET 參數。你想要跳轉到下一個結果頁面嗎？[Y/n]" % len(links)
            #message += "for your search dork expression, but none of them "
            #message += "have GET parameters to test for SQL injection. "
            #message += "Do you want to skip to the next result page? [Y/n]"

            if not readInput(message, default='Y', boolean=True):
                raise SqlmapSilentQuitException
            else:
                conf.googlePage += 1

def _setStdinPipeTargets():
    if conf.url:
        return

    if isinstance(conf.stdinPipe, _collections.Iterable):
        infoMsg = "使用 'STDIN' 解析目標列表"
        logger.info(infoMsg)

        class _(object):
            def __init__(self):
                self.__rest = OrderedSet()

            def __iter__(self):
                return self

            def __next__(self):
                return self.next()

            def next(self):
                try:
                    line = next(conf.stdinPipe)
                except (IOError, OSError, TypeError, UnicodeDecodeError):
                    line = None

                if line:
                    match = re.search(r"\b(https?://[^\s'\"]+|[\w.]+\.\w{2,3}[/\w+]*\?[^\s'\"]+)", line, re.I)
                    if match:
                        return (match.group(0), conf.method, conf.data, conf.cookie, None)
                elif self.__rest:
                    return self.__rest.pop()

                raise StopIteration()

            def add(self, elem):
                self.__rest.add(elem)

        kb.targets = _()

def _setBulkMultipleTargets():
    if not conf.bulkFile:
        return

    conf.bulkFile = safeExpandUser(conf.bulkFile)

    infoMsg = "從 '%s' 解析多個目標列表" % conf.bulkFile
    logger.info(infoMsg)

    if not checkFile(conf.bulkFile, False):
        errMsg = "指定的批量文件不存在"
        #errMsg += "does not exist"
        raise SqlmapFilePathException(errMsg)

    found = False
    for line in getFileItems(conf.bulkFile):
        if conf.scope and not re.search(conf.scope, line, re.I):
            continue

        if re.match(r"[^ ]+\?(.+)", line, re.I) or kb.customInjectionMark in line or conf.data:
            found = True
            kb.targets.add((line.strip(), conf.method, conf.data, conf.cookie, None))

    if not found and not conf.forms and not conf.crawlDepth:
        warnMsg = "未找到可用的鏈接 (帶有 GET 參數)"
        logger.warning(warnMsg)

def _findPageForms():
    if not conf.forms or conf.crawlDepth:
        return

    if conf.url and not checkConnection():
        return

    found = False
    infoMsg = "正在搜索表單"
    logger.info(infoMsg)

    if not any((conf.bulkFile, conf.googleDork)):
        page, _, _ = Request.queryPage(content=True, ignoreSecondOrder=True)
        if findPageForms(page, conf.url, True, True):
            found = True
    else:
        if conf.bulkFile:
            targets = getFileItems(conf.bulkFile)
        elif conf.googleDork:
            targets = [_[0] for _ in kb.targets]
            kb.targets.clear()
        else:
            targets = []

        for i in xrange(len(targets)):
            try:
                target = targets[i].strip()

                if not re.search(r"(?i)\Ahttp[s]*://", target):
                    target = "http://%s" % target

                page, _, _ = Request.getPage(url=target.strip(), cookie=conf.cookie, crawling=True, raise404=False)
                if findPageForms(page, target, False, True):
                    found = True

                if conf.verbose in (1, 2):
                    status = '%d/%d 個連接已請求完成 (%d%%)' % (i + 1, len(targets), round(100.0 * (i + 1) / len(targets)))
                    dataToStdout("\r[%s] [信息] %s" % (time.strftime("%X"), status), True)
            except KeyboardInterrupt:
                break
            except Exception as ex:
                errMsg = "在 '%s' 上搜索表單時出現問題 ('%s')" % (target, getSafeExString(ex))
                logger.error(errMsg)

    if not found:
        warnMsg = "未找到表單"
        logger.warning(warnMsg)

def _setDBMSAuthentication():
    """
    Check and set the DBMS authentication credentials to run statements as
    another user, not the session user
    """

    if not conf.dbmsCred:
        return

    debugMsg = "設置 DBMS 的身份驗證憑據"
    logger.debug(debugMsg)

    match = re.search(r"^(.+?):(.*?)$", conf.dbmsCred)

    if not match:
        errMsg = "DBMS 的身份驗證憑據值必須是用戶名:密碼的格式"
        #errMsg += "username:password"
        raise SqlmapSyntaxException(errMsg)

    conf.dbmsUsername = match.group(1)
    conf.dbmsPassword = match.group(2)

def _setMetasploit():
    if not conf.osPwn and not conf.osSmb and not conf.osBof:
        return

    debugMsg = "設置接管的帶外功能"
    logger.debug(debugMsg)

    msfEnvPathExists = False

    if IS_WIN:
        try:
            __import__("win32file")
        except ImportError:
            errMsg = "sqlmap 需要第三方模塊 'pywin32' 才能在 Windows 上使用 Metasploit 功能。你可以從 'https://github.com/mhammond/pywin32' 下載它"
            #errMsg += "in order to use Metasploit functionalities on "
            #errMsg += "Windows. You can download it from "
            #errMsg += "'https://github.com/mhammond/pywin32'"
            raise SqlmapMissingDependence(errMsg)

        if not conf.msfPath:
            for candidate in os.environ.get("PATH", "").split(';'):
                if all(_ in candidate for _ in ("metasploit", "bin")):
                    conf.msfPath = os.path.dirname(candidate.rstrip('\\'))
                    break

    if conf.osSmb:
        isAdmin = runningAsAdmin()

        if not isAdmin:
            #errMsg = "you need to run sqlmap as an administrator "
            errMsg = "如果你想執行 SMB 中繼攻擊,你需要以管理員身份運行 sqlmap,因為它需要監聽用戶指定的 SMB TCP 端口以接收連接嘗試"
            #errMsg += "it will need to listen on a user-specified SMB "
            #errMsg += "TCP port for incoming connection attempts"
            raise SqlmapMissingPrivileges(errMsg)

    if conf.msfPath:
        for path in (conf.msfPath, os.path.join(conf.msfPath, "bin")):
            if any(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                conf.msfPath = path
                break

        if msfEnvPathExists:
            debugMsg = "提供的 Metasploit Framework 路徑 '%s' 是有效的" % conf.msfPath
            #debugMsg += "'%s' is valid" % conf.msfPath
            logger.debug(debugMsg)
        else:
            warnMsg = "提供的 Metasploit Framework 路徑 '%s' 無效。可能的原因是路徑不存在,或者所需的 Metasploit 可執行文件 (msfcli、msfconsole、msfencode 和 msfpayload) 中的一個或多個不存在" % conf.msfPath
            #warnMsg += "'%s' is not valid. The cause could " % conf.msfPath
            #warnMsg += "be that the path does not exists or that one "
            #warnMsg += "or more of the needed Metasploit executables "
            #warnMsg += "within msfcli, msfconsole, msfencode and "
            #warnMsg += "msfpayload do not exist"
            logger.warning(warnMsg)
    else:
        warnMsg = "你沒有提供 Metasploit Framework 安裝的本地路徑"
        #warnMsg += "Framework is installed"
        logger.warning(warnMsg)

    if not msfEnvPathExists:
        warnMsg = "sqlmap 將在環境路徑中查找 Metasploit Framework 的安裝"
        #warnMsg += "installation inside the environment path(s)"
        logger.warning(warnMsg)

        envPaths = os.environ.get("PATH", "").split(";" if IS_WIN else ":")

        for envPath in envPaths:
            envPath = envPath.replace(";", "")

            if any(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                if msfEnvPathExists:
                    infoMsg = "在 '%s' 路徑中找到了已安裝的 Metasploit Framework" % envPath
                    #infoMsg += "installed in the '%s' path" % envPath
                    logger.info(infoMsg)

                    conf.msfPath = envPath

                    break

    if not msfEnvPathExists:
        errMsg = "無法找到 Metasploit Framework 安裝。你可以在 'https://www.metasploit.com/download/' 獲取它"
        #errMsg += "You can get it at 'https://www.metasploit.com/download/'"
        raise SqlmapFilePathException(errMsg)

def _setWriteFile():
    if not conf.fileWrite:
        return

    debugMsg = "設置寫文件功能"
    logger.debug(debugMsg)

    if not os.path.exists(conf.fileWrite):
        errMsg = "提供的本地文件 '%s' 不存在" % conf.fileWrite
        raise SqlmapFilePathException(errMsg)

    if not conf.fileDest:
        errMsg = "你沒有提供後端 DBMS 的絕對路徑,你想要將本地文件 '%s' 寫入哪裡" % conf.fileWrite
        #errMsg += "where you want to write the local file '%s'" % conf.fileWrite
        raise SqlmapMissingMandatoryOptionException(errMsg)

    conf.fileWriteType = getFileType(conf.fileWrite)

def _setOS():
    """
    Force the back-end DBMS operating system option.
    """

    if not conf.os:
        return

    if conf.os.lower() not in SUPPORTED_OS:
        errMsg = "你提供了一個不受支持的後端 DBMS 操作系統。支持的 DBMS 操作系統包括 %s。" % ', '.join([o.capitalize() for o in SUPPORTED_OS])
        errMsg += "如果你不知道後端 DBMS 的底層操作系統,請不要提供它,sqlmap 將為你進行指紋識別。"
        #errMsg += "and file system access are %s. " % ', '.join([o.capitalize() for o in SUPPORTED_OS])
        #errMsg += "If you do not know the back-end DBMS underlying OS, "
        #errMsg += "do not provide it and sqlmap will fingerprint it for "
        #errMsg += "you."
        raise SqlmapUnsupportedDBMSException(errMsg)

    debugMsg = "強制後端 DBMS 操作系統為用戶定義的值 '%s'" % conf.os
    #debugMsg += "value '%s'" % conf.os
    logger.debug(debugMsg)

    Backend.setOs(conf.os)

def _setTechnique():
    validTechniques = sorted(getPublicTypeMembers(PAYLOAD.TECHNIQUE), key=lambda x: x[1])
    validLetters = [_[0][0].upper() for _ in validTechniques]

    if conf.technique and isinstance(conf.technique, six.string_types):
        _ = []

        for letter in conf.technique.upper():
            if letter not in validLetters:
                errMsg = "--technique 的值必須是由字母 %s 組成的字符串。請參考用戶手冊獲取詳細信息" % ", ".join(validLetters)
                #errMsg += "by the letters %s. Refer to the " % ", ".join(validLetters)
                #errMsg += "user's manual for details"
                raise SqlmapSyntaxException(errMsg)

            for validTech, validInt in validTechniques:
                if letter == validTech[0]:
                    _.append(validInt)
                    break

        conf.technique = _

def _setDBMS():
    """
    Force the back-end DBMS option.
    """

    if not conf.dbms:
        return

    debugMsg = "強制後端 DBMS 為用戶定義的值"
    logger.debug(debugMsg)

    conf.dbms = conf.dbms.lower()
    regex = re.search(r"%s ([\d\.]+)" % ("(%s)" % "|".join(SUPPORTED_DBMS)), conf.dbms, re.I)

    if regex:
        conf.dbms = regex.group(1)
        Backend.setVersion(regex.group(2))

    if conf.dbms not in SUPPORTED_DBMS:
        errMsg = "你提供了一個不受支持的後端數據庫管理系統。支持的 DBMS 如下:%s。" % ', '.join(sorted((_ for _ in (list(DBMS_DICT) + getPublicTypeMembers(FORK, True))), key=str.lower))
        errMsg += "如果你不知道後端 DBMS,請不要提供它,sqlmap 將為你進行指紋識別。"
        #errMsg += "If you do not know the back-end DBMS, do not provide "
        #errMsg += "it and sqlmap will fingerprint it for you."
        raise SqlmapUnsupportedDBMSException(errMsg)

    for dbms, aliases in DBMS_ALIASES:
        if conf.dbms in aliases:
            conf.dbms = dbms

            break

def _listTamperingFunctions():
    """
    Lists available tamper functions
    """

    if conf.listTampers:
        infoMsg = "列出可用的繞過防護腳本\n"
        logger.info(infoMsg)

        for script in sorted(glob.glob(os.path.join(paths.SQLMAP_TAMPER_PATH, "*.py"))):
            content = openFile(script, "rb").read()
            match = re.search(r'(?s)__priority__.+"""(.+)"""', content)
            if match:
                comment = match.group(1).strip()
                dataToStdout("* %s - %s\n" % (setColor(os.path.basename(script), "yellow"), re.sub(r" *\n *", " ", comment.split("\n\n")[0].strip())))

def _setTamperingFunctions():
    """
    Loads tampering functions from given script(s)
    """

    if conf.tamper:
        last_priority = PRIORITY.HIGHEST
        check_priority = True
        resolve_priorities = False
        priorities = []

        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.tamper):
            found = False

            path = safeFilepathEncode(paths.SQLMAP_TAMPER_PATH)
            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                elif os.path.exists(os.path.join(path, script if script.endswith(".py") else "%s.py" % script)):
                    script = os.path.join(path, script if script.endswith(".py") else "%s.py" % script)

                elif not os.path.exists(script):
                    errMsg = "繞過防護腳本 '%s' 不存在" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "繞過防護腳本 '%s' 應該有一個擴展名 '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "在選項 '--tamper' 中提供了無效的字符"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "加載 tamper（繞過防護腳本）模塊 '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                #errMsg = "make sure that there is an empty file '__init__.py' "
                errMsg = "確保繞過防護腳本目錄 '%s' 中有一個空的文件 '__init__.py'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("無法導入 tamper（繞過防護腳本）模塊'%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            priority = PRIORITY.NORMAL if not hasattr(module, "__priority__") else module.__priority__
            priority = priority if priority is not None else PRIORITY.LOWEST

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "tamper" and (hasattr(inspect, "signature") and all(_ in inspect.signature(function).parameters for _ in ("payload", "kwargs")) or inspect.getargspec(function).args and inspect.getargspec(function).keywords == "kwargs"):
                    found = True
                    kb.tamperFunctions.append(function)
                    function.__name__ = module.__name__

                    if check_priority and priority > last_priority:
                        message = "看起來你可能混淆了繞過防護腳本的順序。你想要自動解決這個問題嗎？[Y/n/q] "
                        #message += "the order of tamper scripts. "
                        #message += "Do you want to auto resolve this? [Y/n/q] "
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            resolve_priorities = False
                        elif choice == 'Q':
                            raise SqlmapUserQuitException
                        else:
                            resolve_priorities = True

                        check_priority = False

                    priorities.append((priority, function))
                    last_priority = priority

                    break
                elif name == "dependencies":
                    try:
                        function()
                    except Exception as ex:
                        errMsg = "檢查 tamper（繞過防護腳本）模塊 '%s' 的依賴項時發生錯誤 ('%s')" % (getUnicode(filename[:-3]), getSafeExString(ex))
                        #errMsg += "for tamper module '%s' ('%s')" % (getUnicode(filename[:-3]), getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)

            if not found:
                errMsg = "繞過防護腳本 '%s' 中缺少函數 'tamper(payload, **kwargs)'" % script
                #errMsg += "in tamper script '%s'" % script
                raise SqlmapGenericException(errMsg)

        if kb.tamperFunctions and len(kb.tamperFunctions) > 3:
            warnMsg = "通常不建議使用過多的繞過防護腳本"
            #warnMsg += "a good idea"
            logger.warning(warnMsg)

        if resolve_priorities and priorities:
            priorities.sort(key=functools.cmp_to_key(lambda a, b: cmp(a[0], b[0])), reverse=True)
            kb.tamperFunctions = []

            for _, function in priorities:
                kb.tamperFunctions.append(function)

def _setPreprocessFunctions():
    """
    Loads preprocess function(s) from given script(s)
    """

    if conf.preprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.preprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "預處理腳本 '%s' 不存在" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "預處理腳本 '%s' 應該有一個擴展名 '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "在選項 '--preprocess' 中提供了無效的字符"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "loading preprocess module '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                #errMsg = "make sure that there is an empty file '__init__.py' "
                errMsg = "確保預處理腳本目錄 '%s' 中有一個空的文件 '__init__.py'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("無法導入預處理模塊'%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                try:
                    if name == "preprocess" and inspect.getargspec(function).args and all(_ in inspect.getargspec(function).args for _ in ("req",)):
                        found = True

                        kb.preprocessFunctions.append(function)
                        function.__name__ = module.__name__

                        break
                except ValueError:  # Note: https://github.com/sqlmapproject/sqlmap/issues/4357
                    pass

            if not found:
                errMsg = "預處理腳本 '%s' 中缺少函數 'preprocess(req)'" % script
                #errMsg += "in preprocess script '%s'" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    function(_urllib.request.Request("http://localhost"))
                except Exception as ex:
                    tbMsg = traceback.format_exc()

                    if conf.debug:
                        dataToStdout(tbMsg)

                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+b").write("#!/usr/bin/env\n\ndef preprocess(req):\n    pass\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+b").write("pass")

                    errMsg = "預處理腳本 '%s' 中的函數 'preprocess(req)' 在測試運行中出現問題 ('%s')。你可以在 '%s' 找到一個模板腳本" % (script, getSafeExString(ex), filename)
                    #errMsg += "in preprocess script '%s' " % script
                    #errMsg += "had issues in a test run ('%s'). " % getSafeExString(ex)
                    #errMsg += "You can find a template script at '%s'" % filename
                    raise SqlmapGenericException(errMsg)

def _setPostprocessFunctions():
    """
    Loads postprocess function(s) from given script(s)
    """

    if conf.postprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.postprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "後處理腳本 '%s' 不存在" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "後處理腳本 '%s' 應該有一個擴展名 '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "在選項 '--postprocess' 中提供了無效的字符"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "loading postprocess module '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                #errMsg = "make sure that there is an empty file '__init__.py' "
                errMsg = "確保後處理腳本目錄 '%s' 中有一個空的文件 '__init__.py'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("無法導入後處理模塊'%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "postprocess" and inspect.getargspec(function).args and all(_ in inspect.getargspec(function).args for _ in ("page", "headers", "code")):
                    found = True

                    kb.postprocessFunctions.append(function)
                    function.__name__ = module.__name__

                    break

            if not found:
                errMsg = "後處理腳本 '%s' 中缺少函數 'postprocess(page, headers=None, code=None)'" % script
                #errMsg += "in postprocess script '%s'" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    _, _, _ = function("", {}, None)
                except:
                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+b").write("#!/usr/bin/env\n\ndef postprocess(page, headers=None, code=None):\n    return page, headers, code\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+b").write("pass")

                    errMsg = "後處理腳本 '%s' 中的函數 'postprocess(page, headers=None, code=None)' 應該返回一個元組 '(page, headers, code)'(注意:在 '%s' 中找到模板腳本)" % (script, filename)
                    #errMsg += "in postprocess script '%s' " % script
                    #errMsg += "should return a tuple '(page, headers, code)' "
                    #errMsg += "(Note: find template script at '%s')" % filename
                    raise SqlmapGenericException(errMsg)

def _setThreads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1

def _setDNSCache():
    """
    Makes a cached version of socket._getaddrinfo to avoid subsequent DNS requests.
    """

    def _getaddrinfo(*args, **kwargs):
        if args in kb.cache.addrinfo:
            return kb.cache.addrinfo[args]

        else:
            kb.cache.addrinfo[args] = socket._getaddrinfo(*args, **kwargs)
            return kb.cache.addrinfo[args]

    if not hasattr(socket, "_getaddrinfo"):
        socket._getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = _getaddrinfo

def _setSocketPreConnect():
    """
    Makes a pre-connect version of socket.create_connection
    """

    if conf.disablePrecon:
        return

    def _thread():
        while kb.get("threadContinue") and not conf.get("disablePrecon"):
            try:
                for key in socket._ready:
                    if len(socket._ready[key]) < SOCKET_PRE_CONNECT_QUEUE_SIZE:
                        s = socket.create_connection(*key[0], **dict(key[1]))
                        with kb.locks.socket:
                            socket._ready[key].append((s, time.time()))
            except KeyboardInterrupt:
                break
            except:
                pass
            finally:
                time.sleep(0.01)

    def create_connection(*args, **kwargs):
        retVal = None

        key = (tuple(args), frozenset(kwargs.items()))
        with kb.locks.socket:
            if key not in socket._ready:
                socket._ready[key] = []

            while len(socket._ready[key]) > 0:
                candidate, created = socket._ready[key].pop(0)
                if (time.time() - created) < PRECONNECT_CANDIDATE_TIMEOUT:
                    retVal = candidate
                    break
                else:
                    try:
                        candidate.shutdown(socket.SHUT_RDWR)
                        candidate.close()
                    except socket.error:
                        pass

        if not retVal:
            retVal = socket._create_connection(*args, **kwargs)

        return retVal

    if not hasattr(socket, "_create_connection"):
        socket._ready = {}
        socket._create_connection = socket.create_connection
        socket.create_connection = create_connection

        thread = threading.Thread(target=_thread)
        setDaemon(thread)
        thread.start()

def _setHTTPHandlers():
    """
    Check and set the HTTP/SOCKS proxy for all HTTP requests.
    """

    with kb.locks.handlers:
        if conf.proxyList:
            conf.proxy = conf.proxyList[0]
            conf.proxyList = conf.proxyList[1:] + conf.proxyList[:1]

            if len(conf.proxyList) > 1:
                infoMsg = "從提供的代理列表文件中加載代理 '%s'" % conf.proxy
                logger.info(infoMsg)

        elif not conf.proxy:
            if conf.hostname in ("localhost", "127.0.0.1") or conf.ignoreProxy:
                proxyHandler.proxies = {}

        if conf.proxy:
            debugMsg = "為所有 HTTP 請求設置 HTTP/SOCKS 代理"
            logger.debug(debugMsg)

            try:
                _ = _urllib.parse.urlsplit(conf.proxy)
            except Exception as ex:
                errMsg = "無效的代理地址 '%s'('%s')" % (conf.proxy, getSafeExString(ex))
                raise SqlmapSyntaxException(errMsg)

            hostnamePort = _.netloc.rsplit(":", 1)

            scheme = _.scheme.upper()
            hostname = hostnamePort[0]
            port = None
            username = None
            password = None

            if len(hostnamePort) == 2:
                try:
                    port = int(hostnamePort[1])
                except:
                    pass  # drops into the next check block

            if not all((scheme, hasattr(PROXY_TYPE, scheme), hostname, port)):
                errMsg = "代理值必須符合格式 '(%s)://address:port'" % "|".join(_[0].lower() for _ in getPublicTypeMembers(PROXY_TYPE))
                raise SqlmapSyntaxException(errMsg)

            if conf.proxyCred:
                _ = re.search(r"\A(.*?):(.*?)\Z", conf.proxyCred)
                if not _:
                    errMsg = "代理身份驗證憑據值必須是用戶名:密碼的格式"
                    #errMsg += "value must be in format username:password"
                    raise SqlmapSyntaxException(errMsg)
                else:
                    username = _.group(1)
                    password = _.group(2)

            if scheme in (PROXY_TYPE.SOCKS4, PROXY_TYPE.SOCKS5):
                proxyHandler.proxies = {}

                if scheme == PROXY_TYPE.SOCKS4:
                    warnMsg = "SOCKS4 不支持解析 (DNS) 名稱 (即可能導致 DNS 洩漏)"
                    singleTimeWarnMessage(warnMsg)

                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if scheme == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, hostname, port, username=username, password=password)
                socks.wrapmodule(_http_client)
            else:
                socks.unwrapmodule(_http_client)

                if conf.proxyCred:
                    # Reference: http://stackoverflow.com/questions/34079/how-to-specify-an-authenticated-proxy-for-a-python-http-connection
                    proxyString = "%s@" % conf.proxyCred
                else:
                    proxyString = ""

                proxyString += "%s:%d" % (hostname, port)
                proxyHandler.proxies = kb.proxies = {"http": proxyString, "https": proxyString}

            proxyHandler.__init__(proxyHandler.proxies)

        if not proxyHandler.proxies:
            for _ in ("http", "https"):
                if hasattr(proxyHandler, "%s_open" % _):
                    delattr(proxyHandler, "%s_open" % _)

        debugMsg = "創建 HTTP 請求打開器對象"
        logger.debug(debugMsg)

        handlers = filterNone([multipartPostHandler, proxyHandler if proxyHandler.proxies else None, authHandler, redirectHandler, rangeHandler, chunkedHandler if conf.chunked else None, httpsHandler])

        if not conf.dropSetCookie:
            if not conf.loadCookies:
                conf.cj = _http_cookiejar.CookieJar()
            else:
                conf.cj = _http_cookiejar.MozillaCookieJar()
                resetCookieJar(conf.cj)

            handlers.append(_urllib.request.HTTPCookieProcessor(conf.cj))

        # Reference: http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html
        if conf.keepAlive:
            warnMsg = "由於其不兼容性,已禁用持久的 HTTP(s) 連接 (Keep-Alive)"
            #warnMsg += "been disabled because of its incompatibility "

            if conf.proxy:
                warnMsg += "與 HTTP(s) 代理不兼容"
                logger.warning(warnMsg)
            elif conf.authType:
                warnMsg += "與身份驗證方法不兼容"
                logger.warning(warnMsg)
            else:
                handlers.append(keepAliveHandler)

        opener = _urllib.request.build_opener(*handlers)
        opener.addheaders = []  # Note: clearing default "User-Agent: Python-urllib/X.Y"
        _urllib.request.install_opener(opener)

def _setSafeVisit():
    """
    Check and set the safe visit options.
    """
    if not any((conf.safeUrl, conf.safeReqFile)):
        return

    if conf.safeReqFile:
        checkFile(conf.safeReqFile)

        raw = readCachedFileContent(conf.safeReqFile)
        match = re.search(r"\A([A-Z]+) ([^ ]+) HTTP/[0-9.]+\Z", raw.split('\n')[0].strip())

        if match:
            kb.safeReq.method = match.group(1)
            kb.safeReq.url = match.group(2)
            kb.safeReq.headers = {}

            for line in raw.split('\n')[1:]:
                line = line.strip()
                if line and ':' in line:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    kb.safeReq.headers[key] = value
                    if key.upper() == HTTP_HEADER.HOST.upper():
                        if not value.startswith("http"):
                            scheme = "http"
                            if value.endswith(":443"):
                                scheme = "https"
                            value = "%s://%s" % (scheme, value)
                        kb.safeReq.url = _urllib.parse.urljoin(value, kb.safeReq.url)
                else:
                    break

            post = None

            if '\r\n\r\n' in raw:
                post = raw[raw.find('\r\n\r\n') + 4:]
            elif '\n\n' in raw:
                post = raw[raw.find('\n\n') + 2:]

            if post and post.strip():
                kb.safeReq.post = post
            else:
                kb.safeReq.post = None
        else:
            errMsg = "安全請求文件的格式無效"
            raise SqlmapSyntaxException(errMsg)
    else:
        if not re.search(r"(?i)\Ahttp[s]*://", conf.safeUrl):
            if ":443/" in conf.safeUrl:
                conf.safeUrl = "https://%s" % conf.safeUrl
            else:
                conf.safeUrl = "http://%s" % conf.safeUrl

    if (conf.safeFreq or 0) <= 0:
        errMsg = "在使用安全訪問功能時,請提供一個有效的安全頻率值 ('>0')('--safe-freq')"
        raise SqlmapSyntaxException(errMsg)

def _setPrefixSuffix():
    if conf.prefix is not None and conf.suffix is not None:
        # Create a custom boundary object for user's supplied prefix
        # and suffix
        boundary = AttribDict()

        boundary.level = 1
        boundary.clause = [0]
        boundary.where = [1, 2, 3]
        boundary.prefix = conf.prefix
        boundary.suffix = conf.suffix

        if " like" in boundary.suffix.lower():
            if "'" in boundary.suffix.lower():
                boundary.ptype = 3
            elif '"' in boundary.suffix.lower():
                boundary.ptype = 5
        elif "'" in boundary.suffix:
            boundary.ptype = 2
        elif '"' in boundary.suffix:
            boundary.ptype = 4
        else:
            boundary.ptype = 1

        # user who provides --prefix/--suffix does not want other boundaries
        # to be tested for
        conf.boundaries = [boundary]

def _setAuthCred():
    """
    Adds authentication credentials (if any) for current target to the password manager
    (used by connection handler)
    """

    if kb.passwordMgr and all(_ is not None for _ in (conf.scheme, conf.hostname, conf.port, conf.authUsername, conf.authPassword)):
        kb.passwordMgr.add_password(None, "%s://%s:%d" % (conf.scheme, conf.hostname, conf.port), conf.authUsername, conf.authPassword)

def _setHTTPAuthentication():
    """
    Check and set the HTTP(s) authentication method (Basic, Digest, Bearer, NTLM or PKI),
    username and password for first three methods, or PEM private key file for
    PKI authentication
    """

    global authHandler

    if not conf.authType and not conf.authCred and not conf.authFile:
        return

    if conf.authFile and not conf.authType:
        conf.authType = AUTH_TYPE.PKI

    elif conf.authType and not conf.authCred and not conf.authFile:
        errMsg = "你指定了 HTTP 身份驗證類型,但沒有提供憑據"
        #errMsg += "did not provide the credentials"
        raise SqlmapSyntaxException(errMsg)

    elif not conf.authType and conf.authCred:
        errMsg = "你指定了 HTTP 身份驗證憑據,但沒有提供類型 (例如 --auth-type=\"basic\")"
        #errMsg += "but did not provide the type (e.g. --auth-type=\"basic\")"
        raise SqlmapSyntaxException(errMsg)

    elif (conf.authType or "").lower() not in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST, AUTH_TYPE.BEARER, AUTH_TYPE.NTLM, AUTH_TYPE.PKI):
        errMsg = "HTTP 身份驗證類型值必須是 Basic、Digest、Bearer、NTLM 或 PKI"
        #errMsg += "Basic, Digest, Bearer, NTLM or PKI"
        raise SqlmapSyntaxException(errMsg)

    if not conf.authFile:
        debugMsg = "設置 HTTP 身份驗證類型和憑據"
        logger.debug(debugMsg)

        authType = conf.authType.lower()

        if authType in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST):
            regExp = "^(.*?):(.*?)$"
            errMsg = "HTTP %s 身份驗證憑據值必須是 '用戶名:密碼' 的格式" % authType
            #errMsg += "value must be in format 'username:password'"
        elif authType == AUTH_TYPE.BEARER:
            conf.httpHeaders.append((HTTP_HEADER.AUTHORIZATION, "Bearer %s" % conf.authCred.strip()))
            return
        elif authType == AUTH_TYPE.NTLM:
            regExp = "^(.*\\\\.*):(.*?)$"
            errMsg = "HTTP NTLM 身份驗證憑據值必須是 'DOMAIN\\用戶名:密碼' 的格式"
            #errMsg += "be in format 'DOMAIN\\username:password'"
        elif authType == AUTH_TYPE.PKI:
            errMsg = "HTTP PKI 身份驗證需要使用選項 `--auth-pki`"
            #errMsg += "usage of option `--auth-file`"
            raise SqlmapSyntaxException(errMsg)

        aCredRegExp = re.search(regExp, conf.authCred)

        if not aCredRegExp:
            raise SqlmapSyntaxException(errMsg)

        conf.authUsername = aCredRegExp.group(1)
        conf.authPassword = aCredRegExp.group(2)

        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()

        _setAuthCred()

        if authType == AUTH_TYPE.BASIC:
            authHandler = SmartHTTPBasicAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.DIGEST:
            authHandler = _urllib.request.HTTPDigestAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.NTLM:
            try:
                from ntlm import HTTPNtlmAuthHandler
            except ImportError:
                errMsg = "sqlmap 需要 Python NTLM 第三方庫以通過 NTLM 進行身份驗證。請從 'https://github.com/mullender/python-ntlm' 下載"
                #errMsg += "in order to authenticate via NTLM. Download from "
                #errMsg += "'https://github.com/mullender/python-ntlm'"
                raise SqlmapMissingDependence(errMsg)

            authHandler = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(kb.passwordMgr)
    else:
        debugMsg = "設置 HTTP(s) 身份驗證 PEM 私鑰"
        logger.debug(debugMsg)

        _ = safeExpandUser(conf.authFile)
        checkFile(_)
        authHandler = HTTPSPKIAuthHandler(_)

def _setHTTPExtraHeaders():
    if conf.headers:
        debugMsg = "設置額外的 HTTP 頭"
        logger.debug(debugMsg)

        if "\\n" in conf.headers:
            conf.headers = conf.headers.replace("\\r\\n", "\\n").split("\\n")
        else:
            conf.headers = conf.headers.replace("\r\n", "\n").split("\n")

        for headerValue in conf.headers:
            if not headerValue.strip():
                continue

            if headerValue.count(':') >= 1:
                header, value = (_.lstrip() for _ in headerValue.split(":", 1))

                if header and value:
                    conf.httpHeaders.append((header, value))
            elif headerValue.startswith('@'):
                checkFile(headerValue[1:])
                kb.headersFile = headerValue[1:]
            else:
                errMsg = "無效的頭部值:%s。有效的頭部格式是 'name:value'" % repr(headerValue).lstrip('u')
                raise SqlmapSyntaxException(errMsg)

    elif not conf.requestFile and len(conf.httpHeaders or []) < 2:
        if conf.encoding:
            conf.httpHeaders.append((HTTP_HEADER.ACCEPT_CHARSET, "%s;q=0.7,*;q=0.1" % conf.encoding))

        # Invalidating any caching mechanism in between
        # Reference: http://stackoverflow.com/a/1383359
        conf.httpHeaders.append((HTTP_HEADER.CACHE_CONTROL, "no-cache"))

def _setHTTPUserAgent():
    """
    Set the HTTP User-Agent header.
    Depending on the user options it can be:

        * The default sqlmap string
        * A default value read as user option
        * A random value read from a list of User-Agent headers from a
          file choosed as user option
    """

    debugMsg = "設置 HTTP User-Agent 頭"
    logger.debug(debugMsg)

    if conf.mobile:
        if conf.randomAgent:
            _ = random.sample([_[1] for _ in getPublicTypeMembers(MOBILES, True)], 1)[0]
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, _))
        else:
            message = "你想要 sqlmap 通過 HTTP User-Agent 頭模擬哪款智能手機 (設備)？\n"
            #message += "through HTTP User-Agent header?\n"
            items = sorted(getPublicTypeMembers(MOBILES, True))

            for count in xrange(len(items)):
                item = items[count]
                message += "[%d] %s%s\n" % (count + 1, item[0], " (default)" if item == MOBILES.IPHONE else "")

            test = readInput(message.rstrip('\n'), default=items.index(MOBILES.IPHONE) + 1)

            try:
                item = items[int(test) - 1]
            except:
                item = MOBILES.IPHONE

            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, item[1]))

    elif conf.agent:
        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, conf.agent))

    elif not conf.randomAgent:
        _ = True

        for header, _ in conf.httpHeaders:
            if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                _ = False
                break

        if _:
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, DEFAULT_USER_AGENT))

    else:
        userAgent = fetchRandomAgent()

        infoMsg = "從文件 '%s' 獲取了隨機的 HTTP User-Agent 頭值 '%s'" % (paths.USER_AGENTS, userAgent)
        #infoMsg += "file '%s'" % paths.USER_AGENTS
        logger.info(infoMsg)

        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, userAgent))

def _setHTTPReferer():
    """
    Set the HTTP Referer
    """

    if conf.referer:
        debugMsg = "設置 HTTP Referer 頭"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.referer))

def _setHTTPHost():
    """
    Set the HTTP Host
    """

    if conf.host:
        debugMsg = "設置 HTTP Host 頭"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.HOST, conf.host))

def _setHTTPCookies():
    """
    Set the HTTP Cookie header
    """

    if conf.cookie:
        debugMsg = "設置 HTTP Cookie 頭"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.COOKIE, conf.cookie))

def _setHostname():
    """
    Set value conf.hostname
    """

    if conf.url:
        try:
            conf.hostname = _urllib.parse.urlsplit(conf.url).netloc.split(':')[0]
        except ValueError as ex:
            errMsg = "解析 URL '%s' 時出現問題 ('%s')" % (conf.url, getSafeExString(ex))
            #errMsg += "parsing an URL '%s' ('%s')" % (conf.url, getSafeExString(ex))
            raise SqlmapDataException(errMsg)

def _setHTTPTimeout():
    """
    Set the HTTP timeout
    """

    if conf.timeout:
        debugMsg = "設置 HTTP 超時時間"
        logger.debug(debugMsg)

        conf.timeout = float(conf.timeout)

        if conf.timeout < 3.0:
            warnMsg = "最小的 HTTP 超時時間為 3 秒,sqlmap 將會重置它"
            #warnMsg += "will going to reset it"
            logger.warning(warnMsg)

            conf.timeout = 3.0
    else:
        conf.timeout = 30.0

    try:
        socket.setdefaulttimeout(conf.timeout)
    except OverflowError as ex:
        raise SqlmapValueException("選項 '--timeout' 使用了無效的值（'%s'）" % getSafeExString(ex))

def _checkDependencies():
    """
    Checks for missing dependencies.
    """

    if conf.dependencies:
        checkDependencies()

def _createHomeDirectories():
    """
    Creates directories inside sqlmap's home directory
    """

    if conf.get("purge"):
        return

    for context in ("output", "history"):
        directory = paths["SQLMAP_%s_PATH" % getUnicode(context).upper()]   # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4363
        try:
            if not os.path.isdir(directory):
                os.makedirs(directory)

            _ = os.path.join(directory, randomStr())
            open(_, "w+b").close()
            os.remove(_)

            if conf.get("outputDir") and context == "output":
                warnMsg = "使用 '%s' 作為 %s 目錄" % (directory, context)
                logger.warning(warnMsg)
        except (OSError, IOError) as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmap%s" % context)
            warnMsg = "無法 %s %s 目錄 '%s'(%s)。" % ("創建" if not os.path.isdir(directory) else "寫入", context, directory, getUnicode(ex))
            warnMsg += "改為使用臨時目錄 '%s'" % getUnicode(tempDir)
            #warnMsg += "Using temporary directory '%s' instead" % getUnicode(tempDir)
            logger.warning(warnMsg)

            paths["SQLMAP_%s_PATH" % context.upper()] = tempDir

def _pympTempLeakPatch(tempDir):  # Cross-referenced function
    raise NotImplementedError

def _createTemporaryDirectory():
    """
    Creates temporary directory for this run.
    """

    if conf.tmpDir:
        try:
            if not os.path.isdir(conf.tmpDir):
                os.makedirs(conf.tmpDir)

            _ = os.path.join(conf.tmpDir, randomStr())

            open(_, "w+b").close()
            os.remove(_)

            tempfile.tempdir = conf.tmpDir

            warnMsg = "將 '%s' 作為臨時目錄使用" % conf.tmpDir
            logger.warning(warnMsg)
        except (OSError, IOError) as ex:
            errMsg = "訪問臨時目錄位置時出現問題 ('%s')" % getSafeExString(ex)
            #errMsg += "temporary directory location(s) ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)
    else:
        try:
            if not os.path.isdir(tempfile.gettempdir()):
                os.makedirs(tempfile.gettempdir())
        except Exception as ex:
            warnMsg = "訪問系統臨時目錄位置時出現問題 ('%s')。請確保剩餘足夠的磁盤空間。如果問題仍然存在,請嘗試將環境變量 'TEMP' 設置為當前用戶可寫入的位置" % getSafeExString(ex)
            #warnMsg += "system's temporary directory location(s) ('%s'). Please " % getSafeExString(ex)
            #warnMsg += "make sure that there is enough disk space left. If problem persists, "
            #warnMsg += "try to set environment variable 'TEMP' to a location "
            #warnMsg += "writeable by the current user"
            logger.warning(warnMsg)

    if "sqlmap" not in (tempfile.tempdir or "") or conf.tmpDir and tempfile.tempdir == conf.tmpDir:
        try:
            tempfile.tempdir = tempfile.mkdtemp(prefix="sqlmap", suffix=str(os.getpid()))
        except:
            tempfile.tempdir = os.path.join(paths.SQLMAP_HOME_PATH, "tmp", "sqlmap%s%d" % (randomStr(6), os.getpid()))

    kb.tempDir = tempfile.tempdir

    if not os.path.isdir(tempfile.tempdir):
        try:
            os.makedirs(tempfile.tempdir)
        except Exception as ex:
            errMsg = "設置臨時目錄位置時出現問題 ('%s')" % getSafeExString(ex)
            #errMsg += "temporary directory location ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)

    conf.tempDirs.append(tempfile.tempdir)

    if six.PY3:
        _pympTempLeakPatch(kb.tempDir)

def _cleanupOptions():
    """
    Cleanup configuration attributes.
    """

    if conf.encoding:
        try:
            codecs.lookup(conf.encoding)
        except LookupError:
            errMsg = "未知的編碼 '%s'" % conf.encoding
            raise SqlmapValueException(errMsg)

    debugMsg = "清理配置參數"
    logger.debug(debugMsg)

    width = getConsoleWidth()

    if conf.eta:
        conf.progressWidth = width - 26
    else:
        conf.progressWidth = width - 46

    for key, value in conf.items():
        if value and any(key.endswith(_) for _ in ("Path", "File", "Dir")):
            if isinstance(value, str):
                conf[key] = safeExpandUser(value)

    if conf.testParameter:
        conf.testParameter = urldecode(conf.testParameter)
        conf.testParameter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.testParameter)]
    else:
        conf.testParameter = []

    if conf.ignoreCode:
        if conf.ignoreCode == IGNORE_CODE_WILDCARD:
            conf.ignoreCode = xrange(0, 1000)
        else:
            try:
                conf.ignoreCode = [int(_) for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.ignoreCode)]
            except ValueError:
                errMsg = "選項 '--ignore-code' 應該包含一個整數值列表或通配符值 '%s'" % IGNORE_CODE_WILDCARD
                raise SqlmapSyntaxException(errMsg)
    else:
        conf.ignoreCode = []

    if conf.abortCode:
        try:
            conf.abortCode = [int(_) for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.abortCode)]
        except ValueError:
            errMsg = "選項 '--abort-code' 應該包含一個整數值列表"
            raise SqlmapSyntaxException(errMsg)
    else:
        conf.abortCode = []

    if conf.paramFilter:
        conf.paramFilter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.paramFilter.upper())]
    else:
        conf.paramFilter = []

    if conf.base64Parameter:
        conf.base64Parameter = urldecode(conf.base64Parameter)
        conf.base64Parameter = conf.base64Parameter.strip()
        conf.base64Parameter = re.split(PARAMETER_SPLITTING_REGEX, conf.base64Parameter)
    else:
        conf.base64Parameter = []

    if conf.agent:
        conf.agent = re.sub(r"[\r\n]", "", conf.agent)

    if conf.user:
        conf.user = conf.user.replace(" ", "")

    if conf.rParam:
        if all(_ in conf.rParam for _ in ('=', ',')):
            original = conf.rParam
            conf.rParam = []
            for part in original.split(';'):
                if '=' in part:
                    left, right = part.split('=', 1)
                    conf.rParam.append(left)
                    kb.randomPool[left] = filterNone(_.strip() for _ in right.split(','))
                else:
                    conf.rParam.append(part)
        else:
            conf.rParam = conf.rParam.replace(" ", "")
            conf.rParam = re.split(PARAMETER_SPLITTING_REGEX, conf.rParam)
    else:
        conf.rParam = []

    if conf.paramDel:
        conf.paramDel = decodeStringEscape(conf.paramDel)

    if conf.skip:
        conf.skip = conf.skip.replace(" ", "")
        conf.skip = re.split(PARAMETER_SPLITTING_REGEX, conf.skip)
    else:
        conf.skip = []

    if conf.cookie:
        conf.cookie = re.sub(r"[\r\n]", "", conf.cookie)

    if conf.delay:
        conf.delay = float(conf.delay)

    if conf.url:
        conf.url = conf.url.strip().lstrip('/')
        if not re.search(r"\A\w+://", conf.url):
            conf.url = "http://%s" % conf.url

    if conf.fileRead:
        conf.fileRead = ntToPosixSlashes(normalizePath(conf.fileRead))

    if conf.fileWrite:
        conf.fileWrite = ntToPosixSlashes(normalizePath(conf.fileWrite))

    if conf.fileDest:
        conf.fileDest = ntToPosixSlashes(normalizePath(conf.fileDest))

    if conf.msfPath:
        conf.msfPath = ntToPosixSlashes(normalizePath(conf.msfPath))

    if conf.tmpPath:
        conf.tmpPath = ntToPosixSlashes(normalizePath(conf.tmpPath))

    if any((conf.googleDork, conf.logFile, conf.bulkFile, conf.forms, conf.crawlDepth, conf.stdinPipe)):
        conf.multipleTargets = True

    if conf.optimize:
        setOptimize()

    if conf.os:
        conf.os = conf.os.capitalize()

    if conf.forceDbms:
        conf.dbms = conf.forceDbms

    if conf.dbms:
        kb.dbmsFilter = []
        for _ in conf.dbms.split(','):
            for dbms, aliases in DBMS_ALIASES:
                if _.strip().lower() in aliases:
                    kb.dbmsFilter.append(dbms)
                    conf.dbms = dbms if conf.dbms and ',' not in conf.dbms else None
                    break

    if conf.uValues:
        conf.uCols = "%d-%d" % (1 + conf.uValues.count(','), 1 + conf.uValues.count(','))

    if conf.testFilter:
        conf.testFilter = conf.testFilter.strip('*+')
        conf.testFilter = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testFilter)

        try:
            re.compile(conf.testFilter)
        except re.error:
            conf.testFilter = re.escape(conf.testFilter)

    if conf.csrfToken:
        original = conf.csrfToken
        try:
            re.compile(conf.csrfToken)

            if re.escape(conf.csrfToken) != conf.csrfToken:
                message = "選項 '--csrf-token' 的提供值是一個正則表達式嗎？[y/N] "
                if not readInput(message, default='N', boolean=True):
                    conf.csrfToken = re.escape(conf.csrfToken)
        except re.error:
            conf.csrfToken = re.escape(conf.csrfToken)
        finally:
            class _(six.text_type):
                pass
            conf.csrfToken = _(conf.csrfToken)
            conf.csrfToken._original = original

    if conf.testSkip:
        conf.testSkip = conf.testSkip.strip('*+')
        conf.testSkip = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testSkip)

        try:
            re.compile(conf.testSkip)
        except re.error:
            conf.testSkip = re.escape(conf.testSkip)

    if "timeSec" not in kb.explicitSettings:
        if conf.tor:
            conf.timeSec = 2 * conf.timeSec
            kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

            #warnMsg = "increasing default value for "
            warnMsg = "將選項 '--time-sec' 的默認值增加到 %d,因為提供了 '--tor' 開關" % conf.timeSec
            #warnMsg += "switch '--tor' was provided"
            logger.warning(warnMsg)
    else:
        kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

    if conf.retries:
        conf.retries = min(conf.retries, MAX_CONNECT_RETRIES)

    if conf.url:
        match = re.search(r"\A(\w+://)?([^/@?]+)@", conf.url)
        if match:
            credentials = match.group(2)
            conf.url = conf.url.replace("%s@" % credentials, "", 1)

            conf.authType = AUTH_TYPE.BASIC
            conf.authCred = credentials if ':' in credentials else "%s:" % credentials

    if conf.code:
        conf.code = int(conf.code)

    if conf.csvDel:
        conf.csvDel = decodeStringEscape(conf.csvDel)

    if conf.torPort and hasattr(conf.torPort, "isdigit") and conf.torPort.isdigit():
        conf.torPort = int(conf.torPort)

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.outputDir:
        paths.SQLMAP_OUTPUT_PATH = os.path.realpath(os.path.expanduser(conf.outputDir))
        setPaths(paths.SQLMAP_ROOT_PATH)

    if conf.string:
        conf.string = decodeStringEscape(conf.string)

    if conf.getAll:
        for _ in WIZARD.ALL:
            conf.__setitem__(_, True)

    if conf.noCast:
        DUMP_REPLACEMENTS.clear()

    if conf.dumpFormat:
        conf.dumpFormat = conf.dumpFormat.upper()

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.col:
        conf.col = re.sub(r"\s*,\s*", ',', conf.col)

    if conf.exclude:
        regex = False
        original = conf.exclude

        if any(_ in conf.exclude for _ in ('+', '*')):
            try:
                re.compile(conf.exclude)
            except re.error:
                pass
            else:
                regex = True

        if not regex:
            conf.exclude = re.sub(r"\s*,\s*", ',', conf.exclude)
            conf.exclude = r"\A%s\Z" % '|'.join(re.escape(_) for _ in conf.exclude.split(','))
        else:
            conf.exclude = re.sub(r"(\w+)\$", r"\g<1>\$", conf.exclude)

        class _(six.text_type):
            pass

        conf.exclude = _(conf.exclude)
        conf.exclude._original = original

    if conf.binaryFields:
        conf.binaryFields = conf.binaryFields.replace(" ", "")
        conf.binaryFields = re.split(PARAMETER_SPLITTING_REGEX, conf.binaryFields)

    envProxy = max(os.environ.get(_, "") for _ in PROXY_ENVIRONMENT_VARIABLES)
    if re.search(r"\A(https?|socks[45])://.+:\d+\Z", envProxy) and conf.proxy is None:
        debugMsg = "使用環境代理 '%s'" % envProxy
        logger.debug(debugMsg)

        conf.proxy = envProxy

    if any((conf.proxy, conf.proxyFile, conf.tor)):
        conf.disablePrecon = True

    if conf.dummy:
        conf.batch = True

    threadData = getCurrentThreadData()
    threadData.reset()

def _cleanupEnvironment():
    """
    Cleanup environment (e.g. from leftovers after --shell).
    """

    if issubclass(_http_client.socket.socket, socks.socksocket):
        socks.unwrapmodule(_http_client)

    if hasattr(socket, "_ready"):
        socket._ready.clear()

def _purge():
    """
    Safely removes (purges) sqlmap data directory.
    """

    if conf.purge:
        purge(paths.SQLMAP_HOME_PATH)

def _setConfAttributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debugMsg = "初始化配置"
    logger.debug(debugMsg)

    conf.authUsername = None
    conf.authPassword = None
    conf.boundaries = []
    conf.cj = None
    conf.dbmsConnector = None
    conf.dbmsHandler = None
    conf.dnsServer = None
    conf.dumpPath = None
    conf.fileWriteType = None
    conf.HARCollectorFactory = None
    conf.hashDB = None
    conf.hashDBFile = None
    conf.httpCollector = None
    conf.httpHeaders = []
    conf.hostname = None
    conf.ipv6 = False
    conf.multipleTargets = False
    conf.outputPath = None
    conf.paramDict = {}
    conf.parameters = {}
    conf.path = None
    conf.port = None
    conf.proxyList = None
    conf.resultsFP = None
    conf.scheme = None
    conf.tests = []
    conf.tempDirs = []
    conf.trafficFP = None

def _setKnowledgeBaseAttributes(flushAll=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debugMsg = "初始化知識庫"
    logger.debug(debugMsg)

    kb.absFilePaths = set()
    kb.adjustTimeDelay = None
    kb.alerted = False
    kb.aliasName = randomStr()
    kb.alwaysRefresh = None
    kb.arch = None
    kb.authHeader = None
    kb.bannerFp = AttribDict()
    kb.base64Originals = {}
    kb.binaryField = False
    kb.browserVerification = None

    kb.brute = AttribDict({"tables": [], "columns": []})
    kb.bruteMode = False

    kb.cache = AttribDict()
    kb.cache.addrinfo = {}
    kb.cache.content = {}
    kb.cache.comparison = {}
    kb.cache.encoding = {}
    kb.cache.alphaBoundaries = None
    kb.cache.hashRegex = None
    kb.cache.intBoundaries = None
    kb.cache.parsedDbms = {}
    kb.cache.regex = {}
    kb.cache.stdev = {}

    kb.captchaDetected = None

    kb.chars = AttribDict()
    kb.chars.delimiter = randomStr(length=6, lowercase=True)
    kb.chars.start = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET), KB_CHARS_BOUNDARY_CHAR)
    kb.chars.stop = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET), KB_CHARS_BOUNDARY_CHAR)
    kb.chars.at, kb.chars.space, kb.chars.dollar, kb.chars.hash_ = ("%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, _, KB_CHARS_BOUNDARY_CHAR) for _ in randomStr(length=4, lowercase=True))

    kb.choices = AttribDict(keycheck=False)
    kb.codePage = None
    kb.commonOutputs = None
    kb.connErrorCounter = 0
    kb.copyExecTest = None
    kb.counters = {}
    kb.customInjectionMark = CUSTOM_INJECTION_MARK_CHAR
    kb.data = AttribDict()
    kb.dataOutputFlag = False

    # Active back-end DBMS fingerprint
    kb.dbms = None
    kb.dbmsFilter = []
    kb.dbmsVersion = [UNKNOWN_DBMS_VERSION]

    kb.delayCandidates = TIME_DELAY_CANDIDATES * [0]
    kb.dep = None
    kb.disableHtmlDecoding = False
    kb.disableShiftTable = False
    kb.dnsMode = False
    kb.dnsTest = None
    kb.docRoot = None
    kb.droppingRequests = False
    kb.dumpColumns = None
    kb.dumpTable = None
    kb.dumpKeyboardInterrupt = False
    kb.dynamicMarkings = []
    kb.dynamicParameter = False
    kb.endDetection = False
    kb.explicitSettings = set()
    kb.extendTests = None
    kb.errorChunkLength = None
    kb.errorIsNone = True
    kb.falsePositives = []
    kb.fileReadMode = False
    kb.fingerprinted = False
    kb.followSitemapRecursion = None
    kb.forcedDbms = None
    kb.forcePartialUnion = False
    kb.forceThreads = None
    kb.forceWhere = None
    kb.forkNote = None
    kb.futileUnion = None
    kb.fuzzUnionTest = None
    kb.heavilyDynamic = False
    kb.headersFile = None
    kb.headersFp = {}
    kb.heuristicDbms = None
    kb.heuristicExtendedDbms = None
    kb.heuristicCode = None
    kb.heuristicMode = False
    kb.heuristicPage = False
    kb.heuristicTest = None
    kb.hintValue = ""
    kb.htmlFp = []
    kb.httpErrorCodes = {}
    kb.inferenceMode = False
    kb.ignoreCasted = None
    kb.ignoreNotFound = False
    kb.ignoreTimeout = False
    kb.identifiedWafs = set()
    kb.injection = InjectionDict()
    kb.injections = []
    kb.jsonAggMode = False
    kb.laggingChecked = False
    kb.lastParserStatus = None

    kb.locks = AttribDict()
    for _ in ("cache", "connError", "count", "handlers", "hint", "identYwaf", "index", "io", "limit", "liveCookies", "log", "socket", "redirect", "request", "value"):
        kb.locks[_] = threading.Lock()

    kb.matchRatio = None
    kb.maxConnectionsFlag = False
    kb.mergeCookies = None
    kb.multiThreadMode = False
    kb.multipleCtrlC = False
    kb.negativeLogic = False
    kb.nchar = True
    kb.nullConnection = None
    kb.oldMsf = None
    kb.orderByColumns = None
    kb.originalCode = None
    kb.originalPage = None
    kb.originalPageTime = None
    kb.originalTimeDelay = None
    kb.originalUrls = dict()

    # Back-end DBMS underlying operating system fingerprint via banner (-b)
    # parsing
    kb.os = None
    kb.osVersion = None
    kb.osSP = None

    kb.pageCompress = True
    kb.pageTemplate = None
    kb.pageTemplates = dict()
    kb.pageEncoding = DEFAULT_PAGE_ENCODING
    kb.pageStable = None
    kb.partRun = None
    kb.permissionFlag = False
    kb.place = None
    kb.postHint = None
    kb.postSpaceToPlus = False
    kb.postUrlEncode = True
    kb.prependFlag = False
    kb.processResponseCounter = 0
    kb.previousMethod = None
    kb.processNonCustom = None
    kb.processUserMarks = None
    kb.proxies = None
    kb.proxyAuthHeader = None
    kb.queryCounter = 0
    kb.randomPool = {}
    kb.reflectiveMechanism = True
    kb.reflectiveCounters = {REFLECTIVE_COUNTER.MISS: 0, REFLECTIVE_COUNTER.HIT: 0}
    kb.requestCounter = 0
    kb.resendPostOnRedirect = None
    kb.resolutionDbms = None
    kb.responseTimes = {}
    kb.responseTimeMode = None
    kb.responseTimePayload = None
    kb.resumeValues = True
    kb.safeCharEncode = False
    kb.safeReq = AttribDict()
    kb.secondReq = None
    kb.serverHeader = None
    kb.singleLogFlags = set()
    kb.skipSeqMatcher = False
    kb.smokeMode = False
    kb.reduceTests = None
    kb.sslSuccess = False
    kb.startTime = time.time()
    kb.stickyDBMS = False
    kb.suppressResumeInfo = False
    kb.tableFrom = None
    kb.technique = None
    kb.tempDir = None
    kb.testMode = False
    kb.testOnlyCustom = False
    kb.testQueryCount = 0
    kb.testType = None
    kb.threadContinue = True
    kb.threadException = False
    kb.uChar = NULL
    kb.udfFail = False
    kb.unionDuplicates = False
    kb.unionTemplate = None
    kb.webSocketRecvCount = None
    kb.wizardMode = False
    kb.xpCmdshellAvailable = False

    if flushAll:
        kb.checkSitemap = None
        kb.headerPaths = {}
        kb.keywords = set(getFileItems(paths.SQL_KEYWORDS))
        kb.lastCtrlCTime = None
        kb.normalizeCrawlingChoice = None
        kb.passwordMgr = None
        kb.postprocessFunctions = []
        kb.preprocessFunctions = []
        kb.skipVulnHost = None
        kb.storeCrawlingChoice = None
        kb.tamperFunctions = []
        kb.targets = OrderedSet()
        kb.testedParams = set()
        kb.userAgents = None
        kb.vainRun = True
        kb.vulnHosts = set()
        kb.wafFunctions = []
        kb.wordlists = None

def _useWizardInterface():
    """
    Presents simple wizard interface for beginner users
    """

    if not conf.wizard:
        return

    logger.info("啟動向導界面")

    while not conf.url:
        message = "請輸入完整的目標 URL (-u):"
        conf.url = readInput(message, default=None, checkBatch=False)

    message = "%s 數據 (--data) [按回車鍵表示無]:" % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
    conf.data = readInput(message, default=None)

    if not (any('=' in _ for _ in (conf.url, conf.data)) or '*' in conf.url):
        warnMsg = "未找到用於測試的 GET 和/或 %s 參數" % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
        warnMsg += "(例如,在 'http://www.site.com/vuln.php?id=1' 中的 GET 參數 'id')"
        if not conf.crawlDepth and not conf.forms:
            warnMsg += "將搜索表單"
            conf.forms = True
        logger.warning(warnMsg)

    choice = None

    while choice is None or choice not in ("", "1", "2", "3"):
        message = "注入難度 (--level/--risk)。請選擇:\n"
        message += "[1] 普通 (默認)\n[2] 中等\n[3] 困難"
        choice = readInput(message, default='1')

        if choice == '2':
            conf.risk = 2
            conf.level = 3
        elif choice == '3':
            conf.risk = 3
            conf.level = 5
        else:
            conf.risk = 1
            conf.level = 1

    if not conf.getAll:
        choice = None

        while choice is None or choice not in ("", "1", "2", "3"):
            message = "枚舉選項 (--banner/--current-user/etc)。請選擇:\n"
            message += "[1] 基礎 (默認)\n[2] 中級\n[3] 全部"
            choice = readInput(message, default='1')

            if choice == '2':
                options = WIZARD.INTERMEDIATE
            elif choice == '3':
                options = WIZARD.ALL
            else:
                options = WIZARD.BASIC

            for _ in options:
                conf.__setitem__(_, True)

    logger.debug("靜音模式啟動 sqlmap.. 它將為您帶來神奇的效果")
    conf.verbose = 0

    conf.batch = True
    conf.threads = 4

    dataToStdout("\nsqlmap 正在運行,請稍候..\n\n")

    kb.wizardMode = True

def _saveConfig():
    """
    Saves the command line options to a sqlmap configuration INI file
    Format.
    """

    if not conf.saveConfig:
        return

    debugMsg = "將命令行選項保存到 sqlmap 配置文件中"
    logger.debug(debugMsg)

    saveConfig(conf, conf.saveConfig)

    infoMsg = "將命令行選項保存到配置文件 '%s'" % conf.saveConfig
    logger.info(infoMsg)

def setVerbosity():
    """
    This function set the verbosity of sqlmap output messages.
    """

    if conf.verbose is None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 0:
        logger.setLevel(logging.ERROR)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 2 and conf.eta:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(CUSTOM_LOGGING.PAYLOAD)
    elif conf.verbose == 4:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_OUT)
    elif conf.verbose >= 5:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_IN)

def _normalizeOptions(inputOptions):
    """
    Sets proper option types
    """

    types_ = {}
    for group in optDict.keys():
        types_.update(optDict[group])

    for key in inputOptions:
        if key in types_:
            value = inputOptions[key]
            if value is None:
                continue

            type_ = types_[key]
            if type_ and isinstance(type_, tuple):
                type_ = type_[0]

            if type_ == OPTION_TYPE.BOOLEAN:
                try:
                    value = bool(value)
                except (TypeError, ValueError):
                    value = False
            elif type_ == OPTION_TYPE.INTEGER:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = 0
            elif type_ == OPTION_TYPE.FLOAT:
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    value = 0.0

            inputOptions[key] = value

def _mergeOptions(inputOptions, overrideOptions):
    """
    Merge command line options with configuration file and default options.

    @param inputOptions: optparse object with command line options.
    @type inputOptions: C{instance}
    """

    if inputOptions.configFile:
        configFileParser(inputOptions.configFile)

    if hasattr(inputOptions, "items"):
        inputOptionsItems = inputOptions.items()
    else:
        inputOptionsItems = inputOptions.__dict__.items()

    for key, value in inputOptionsItems:
        if key not in conf or value not in (None, False) or overrideOptions:
            conf[key] = value

    if not conf.api:
        for key, value in conf.items():
            if value is not None:
                kb.explicitSettings.add(key)

    for key, value in defaults.items():
        if hasattr(conf, key) and conf[key] is None:
            conf[key] = value

            if conf.unstable:
                if key in ("timeSec", "retries", "timeout"):
                    conf[key] *= 2

    if conf.unstable:
        conf.forcePartial = True

    lut = {}
    for group in optDict.keys():
        lut.update((_.upper(), _) for _ in optDict[group])

    envOptions = {}
    for key, value in os.environ.items():
        if key.upper().startswith(SQLMAP_ENVIRONMENT_PREFIX):
            _ = key[len(SQLMAP_ENVIRONMENT_PREFIX):].upper()
            if _ in lut:
                envOptions[lut[_]] = value

    if envOptions:
        _normalizeOptions(envOptions)
        for key, value in envOptions.items():
            conf[key] = value

    mergedOptions.update(conf)

def _setTrafficOutputFP():
    if conf.trafficFile:
        infoMsg = "設置用於記錄 HTTP 流量的文件"
        logger.info(infoMsg)

        conf.trafficFP = openFile(conf.trafficFile, "w+")

def _setupHTTPCollector():
    if not conf.harFile:
        return

    conf.httpCollector = HTTPCollectorFactory(conf.harFile).create()

def _setDNSServer():
    if not conf.dnsDomain:
        return

    infoMsg = "設置 DNS 服務器實例"
    logger.info(infoMsg)

    isAdmin = runningAsAdmin()

    if isAdmin:
        try:
            conf.dnsServer = DNSServer()
            conf.dnsServer.run()
        except socket.error as ex:
            errMsg = "設置 DNS 服務器實例時出錯 ('%s)" % getSafeExString(ex)
            #errMsg += "DNS server instance ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)
    else:
        #errMsg = "you need to run sqlmap as an administrator "
        errMsg = "如果您想執行 DNS 數據洩漏攻擊,則需要以管理員身份運行 sqlmap,因為它需要監聽特權 UDP 端口 53 來接收地址解析請求"
        #errMsg += "as it will need to listen on privileged UDP port 53 "
        #errMsg += "for incoming address resolution attempts"
        raise SqlmapMissingPrivileges(errMsg)

def _setProxyList():
    if not conf.proxyFile:
        return

    conf.proxyList = []
    for match in re.finditer(r"(?i)((http[^:]*|socks[^:]*)://)?([\w\-.]+):(\d+)", readCachedFileContent(conf.proxyFile)):
        _, type_, address, port = match.groups()
        conf.proxyList.append("%s://%s:%s" % (type_ or "http", address, port))

def _setTorProxySettings():
    if not conf.tor:
        return

    if conf.torType == PROXY_TYPE.HTTP:
        _setTorHttpProxySettings()
    else:
        _setTorSocksProxySettings()

def _setTorHttpProxySettings():
    infoMsg = "設置 Tor HTTP 代理設置"
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_HTTP_PORTS if not conf.torPort else (conf.torPort,))

    if port:
        conf.proxy = "http://%s:%d" % (LOCALHOST, port)
    else:
        errMsg = "無法與 Tor HTTP 代理建立連接。請確保您已安裝和設置了 Tor(捆綁包),以便能夠成功使用開關 '--tor'。"
        #errMsg += "Please make sure that you have Tor (bundle) installed and setup "
        #errMsg += "so you could be able to successfully use switch '--tor' "
        raise SqlmapConnectionException(errMsg)

    if not conf.checkTor:
        warnMsg = "在訪問 Tor 匿名網絡時,根據您自己的方便使用開關 '--check-tor',因為各種 '捆綁包' 的默認設置存在已知問題 (例如 Vidalia)"
        #warnMsg += "your own convenience when accessing "
        #warnMsg += "Tor anonymizing network because of "
        #warnMsg += "known issues with default settings of various 'bundles' "
        #warnMsg += "(e.g. Vidalia)"
        logger.warning(warnMsg)

def _setTorSocksProxySettings():
    infoMsg = "設置 Tor SOCKS 代理設置"
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_SOCKS_PORTS if not conf.torPort else (conf.torPort,))

    if not port:
        errMsg = "無法與 Tor SOCKS 代理建立連接。請確保您已安裝和設置了 Tor 服務,以便能夠成功使用開關 '--tor'。"
        #errMsg += "Please make sure that you have Tor service installed and setup "
        #errMsg += "so you could be able to successfully use switch '--tor' "
        raise SqlmapConnectionException(errMsg)

    # SOCKS5 to prevent DNS leaks (http://en.wikipedia.org/wiki/Tor_%28anonymity_network%29)
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if conf.torType == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, LOCALHOST, port)
    socks.wrapmodule(_http_client)

def _setHttpChunked():
    if conf.chunked and conf.data:
        if hasattr(_http_client.HTTPConnection, "_set_content_length"):
            _http_client.HTTPConnection._set_content_length = lambda self, *args, **kwargs: None
        else:
            def putheader(self, header, *values):
                if header != HTTP_HEADER.CONTENT_LENGTH:
                    self._putheader(header, *values)

            if not hasattr(_http_client.HTTPConnection, "_putheader"):
                _http_client.HTTPConnection._putheader = _http_client.HTTPConnection.putheader

            _http_client.HTTPConnection.putheader = putheader

def _checkWebSocket():
    if conf.url and (conf.url.startswith("ws:/") or conf.url.startswith("wss:/")):
        try:
            from websocket import ABNF
        except ImportError:
            errMsg = "sqlmap 需要第三方模塊 'websocket-client' 以便使用 WebSocket 功能"
            #errMsg += "in order to use WebSocket functionality"
            raise SqlmapMissingDependence(errMsg)

def _checkTor():
    if not conf.checkTor:
        return

    infoMsg = "檢查 Tor 連接"
    logger.info(infoMsg)

    try:
        page, _, _ = Request.getPage(url="https://check.torproject.org/api/ip", raise404=False)
        tor_status = json.loads(page)
    except (SqlmapConnectionException, TypeError, ValueError):
        tor_status = None

    if not tor_status or not tor_status.get("IsTor"):
        errMsg = "似乎 Tor 沒有正確設置。請嘗試使用選項 '--tor-type' 和/或 '--tor-port'"
        raise SqlmapConnectionException(errMsg)
    else:
        infoMsg = "Tor 正在正確使用"
        logger.info(infoMsg)

def _basicOptionValidation():
    if conf.limitStart is not None and not (isinstance(conf.limitStart, int) and conf.limitStart > 0):
        errMsg = "選項 '--start' (limitStart) 的值必須是大於零的整數 (>0)"
        raise SqlmapSyntaxException(errMsg)

    if conf.limitStop is not None and not (isinstance(conf.limitStop, int) and conf.limitStop > 0):
        errMsg = "選項 '--stop' (limitStop) 的值必須是大於零的整數 (>0)"
        raise SqlmapSyntaxException(errMsg)

    if conf.level is not None and not (isinstance(conf.level, int) and conf.level >= 1 and conf.level <= 5):
        errMsg = "選項 '--level' 的值必須是範圍在 [1, 5] 內的整數"
        raise SqlmapSyntaxException(errMsg)

    if conf.risk is not None and not (isinstance(conf.risk, int) and conf.risk >= 1 and conf.risk <= 3):
        errMsg = "選項 '--risk' 的值必須是範圍在 [1, 3] 內的整數"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.limitStart, int) and conf.limitStart > 0 and \
       isinstance(conf.limitStop, int) and conf.limitStop < conf.limitStart:
        warnMsg = "使用大於 --stop (limitStop) 選項值的 --start (limitStart) 選項被視為不穩定"
        logger.warning(warnMsg)

    if isinstance(conf.firstChar, int) and conf.firstChar > 0 and \
       isinstance(conf.lastChar, int) and conf.lastChar < conf.firstChar:
        errMsg = "選項 --first (firstChar) 的值必須小於或等於 --last (lastChar) 選項的值"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFile and not any((conf.randomAgent, conf.mobile, conf.agent, conf.requestFile)):
        warnMsg = "在使用 --proxy-file 選項時,強烈建議同時使用 --random-agent 開關"
        #warnMsg += "using option '--proxy-file'"
        logger.warning(warnMsg)

    if conf.textOnly and conf.nullConnection:
        errMsg = "開關 --text-only 與開關 --null-connection 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.uValues and conf.uChar:
        errMsg = "選項 --union-values 與選項 --union-char 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.base64Parameter and conf.tamper:
        errMsg = "選項 --base64 與選項 --tamper 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.eta and conf.verbose > defaults.verbose:
        errMsg = "開關 --eta 與選項 -v 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.secondUrl and conf.secondReq:
        errMsg = "選項 --second-url 與選項 --second-req 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.url:
        errMsg = "選項 -d 與選項 -u (--url) 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.dbms:
        errMsg = "選項 -d 與選項 --dbms 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.titles and conf.nullConnection:
        errMsg = "開關 --titles 與開關 --null-connection 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.search:
        errMsg = "開關 --dump 與開關 --search 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.chunked and not any((conf.data, conf.requestFile, conf.forms)):
        errMsg = "開關 --chunked 需要使用 (POST) 選項/開關 '--data'、'-r' 或 '--forms'"
        raise SqlmapSyntaxException(errMsg)

    if conf.api and not conf.configFile:
        errMsg = "開關 --api 需要使用選項 '-c'"
        raise SqlmapSyntaxException(errMsg)

    if conf.data and conf.nullConnection:
        errMsg = "選項 --data 與開關 --null-connection 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.nullConnection:
        errMsg = "選項 --string 與開關 --null-connection 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.notString and conf.nullConnection:
        errMsg = "選項 --not-string 與開關 --null-connection 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.osPwn:
        errMsg = "選項 --tor 與開關 --os-pwn 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.noCast and conf.hexConvert:
        errMsg = "開關 --no-cast 與開關 --hex 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlDepth:
        try:
            xrange(conf.crawlDepth)
        except OverflowError as ex:
            errMsg = "選項 '--crawl' 使用了無效的值 ('%s')" % getSafeExString(ex)
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpAll and conf.search:
        errMsg = "開關 '--dump-all' 與開關 '--search' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.notString:
        errMsg = "選項 '--string' 與開關 '--not-string' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp and conf.nullConnection:
        errMsg = "選項 '--regexp' 與開關 '--null-connection' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp:
        try:
            re.compile(conf.regexp)
        except Exception as ex:
            errMsg = "無效的正則表達式 '%s' ('%s')" % (conf.regexp, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.paramExclude:
        if re.search(r"\A\w+,", conf.paramExclude):
            conf.paramExclude = r"\A(%s)\Z" % ('|'.join(re.escape(_).strip() for _ in conf.paramExclude.split(',')))

        try:
            re.compile(conf.paramExclude)
        except Exception as ex:
            errMsg = "無效的正則表達式 '%s' ('%s')" % (conf.paramExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.retryOn:
        try:
            re.compile(conf.retryOn)
        except Exception as ex:
            errMsg = "無效的正則表達式 '%s' ('%s')" % (conf.retryOn, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

        if conf.retries == defaults.retries:
            conf.retries = 5 * conf.retries

            #warnMsg = "increasing default value for "
            warnMsg = "將選項 '--retries' 的默認值增加到 %d,因為提供了選項 '--retry-on'" % conf.retries
            #warnMsg += "option '--retry-on' was provided"
            logger.warning(warnMsg)

    if conf.cookieDel and len(conf.cookieDel) != 1:
        errMsg = "選項 '--cookie-del' 應該包含一個字符 (例如 ';')"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude:
        try:
            re.compile(conf.crawlExclude)
        except Exception as ex:
            errMsg = "無效的正則表達式 '%s' ('%s')" % (conf.crawlExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.scope:
        try:
            re.compile(conf.scope)
        except Exception as ex:
            errMsg = "無效的正則表達式 '%s' ('%s')" % (conf.scope, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.dumpAll:
        errMsg = "開關 '--dump' 與開關 '--dump-all' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.predictOutput and (conf.threads > 1 or conf.optimize):
        errMsg = "開關 '--predict-output' 與選項 '--threads' 和開關 '-o' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.threads > MAX_NUMBER_OF_THREADS and not conf.get("skipThreadCheck"):
        errMsg = "最大使用線程數為 %d,以避免潛在的連接問題" % MAX_NUMBER_OF_THREADS
        raise SqlmapSyntaxException(errMsg)

    if conf.forms and not any((conf.url, conf.googleDork, conf.bulkFile)):
        errMsg = "開關 '--forms' 需要使用選項 '-u' ('--url')、'-g' 或 '-m'"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude and not conf.crawlDepth:
        errMsg = "選項 '--crawl-exclude' 需要使用開關 '--crawl'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safePost and not conf.safeUrl:
        errMsg = "選項 '--safe-post' 需要使用選項 '--safe-url'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeFreq and not any((conf.safeUrl, conf.safeReqFile)):
        errMsg = "選項 '--safe-freq' 需要使用選項 '--safe-url' 或 '--safe-req'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeReqFile and any((conf.safeUrl, conf.safePost)):
        errMsg = "選項 '--safe-req' 與選項 '--safe-url' 和選項 '--safe-post' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfUrl and not conf.csrfToken:
        errMsg = "選項 '--csrf-url' 需要使用選項 '--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfMethod and not conf.csrfToken:
        errMsg = "選項 '--csrf-method' 需要使用選項 '--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfData and not conf.csrfToken:
        errMsg = "選項 '--csrf-data' 需要使用選項 '--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfToken and conf.threads > 1:
        errMsg = "選項 '--csrf-url' 與選項 '--threads' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.requestFile and conf.url and conf.url != DUMMY_URL:
        errMsg = "選項 '-r' 與選項 '-u' ('--url') 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.proxy:
        errMsg = "選項 '-d' 與選項 '--proxy' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.tor:
        errMsg = "選項 '-d' 與開關 '--tor' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if not conf.technique:
        errMsg = "選項 '--technique' 不能為空"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.ignoreProxy:
        errMsg = "開關 '--tor' 與開關 '--ignore-proxy' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.proxy:
        errMsg = "開關 '--tor' 與選項 '--proxy' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.proxyFile:
        errMsg = "開關 '--proxy' 與選項 '--proxy-file' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFreq and not conf.proxyFile:
        errMsg = "選項 '--proxy-freq' 需要使用選項 '--proxy-file'"
        raise SqlmapSyntaxException(errMsg)

    if conf.checkTor and not any((conf.tor, conf.proxy)):
        errMsg = "開關 '--check-tor' 需要使用開關 '--tor'(或使用 HTTP 代理地址的選項 '--proxy')"
        raise SqlmapSyntaxException(errMsg)

    if conf.torPort is not None and not (isinstance(conf.torPort, int) and conf.torPort >= 0 and conf.torPort <= 65535):
        errMsg = "選項 '--tor-port' 的值必須在範圍 [0, 65535] 內"
        raise SqlmapSyntaxException(errMsg)

    if conf.torType not in getPublicTypeMembers(PROXY_TYPE, True):
        errMsg = "選項 '--tor-type' 接受以下值之一:%s" % ", ".join(getPublicTypeMembers(PROXY_TYPE, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpFormat not in getPublicTypeMembers(DUMP_FORMAT, True):
        errMsg = "選項 '--dump-format' 接受以下值之一:%s" % ", ".join(getPublicTypeMembers(DUMP_FORMAT, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.uValues and (not re.search(r"\A['\w\s.,()%s-]+\Z" % CUSTOM_INJECTION_MARK_CHAR, conf.uValues) or conf.uValues.count(CUSTOM_INJECTION_MARK_CHAR) != 1):
        errMsg = "option '--union-values' must contain valid UNION column values, along with the injection position "
        errMsg += "(例如 'NULL,1,%s,NULL')" % CUSTOM_INJECTION_MARK_CHAR
        raise SqlmapSyntaxException(errMsg)

    if conf.skip and conf.testParameter:
        if intersect(conf.skip, conf.testParameter):
            errMsg = "選項 '--skip' 與選項 '-p' 不兼容"
            raise SqlmapSyntaxException(errMsg)

    if conf.rParam and conf.testParameter:
        if intersect(conf.rParam, conf.testParameter):
            errMsg = "選項 '--randomize' 與選項 '-p' 不兼容"
            raise SqlmapSyntaxException(errMsg)

    if conf.mobile and conf.agent:
        errMsg = "開關 '--mobile' 與選項 '--user-agent' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.ignoreProxy:
        errMsg = "選項 '--proxy' 與開關 '--ignore-proxy' 不兼容"
        raise SqlmapSyntaxException(errMsg)

    if conf.alert and conf.alert.startswith('-'):
        errMsg = "選項 '--alert' 的值必須是有效的操作系統命令"
        raise SqlmapSyntaxException(errMsg)

    if conf.timeSec < 1:
        errMsg = "選項 '--time-sec' 的值必須是正整數"
        raise SqlmapSyntaxException(errMsg)

    if conf.hashFile and any((conf.direct, conf.url, conf.logFile, conf.bulkFile, conf.googleDork, conf.configFile, conf.requestFile, conf.updateAll, conf.smokeTest, conf.wizard, conf.dependencies, conf.purge, conf.listTampers)):
        errMsg = "選項 '--crack' 應作為獨立選項使用"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.uCols, six.string_types):
        if not conf.uCols.isdigit() and ("-" not in conf.uCols or len(conf.uCols.split("-")) != 2):
            errMsg = "選項 '--union-cols' 的值必須是帶有連字符的範圍 "
            errMsg += "(例如 1-10) 或整數值 (例如 5)"
            raise SqlmapSyntaxException(errMsg)

    if conf.dbmsCred and ':' not in conf.dbmsCred:
        errMsg = "選項 '--dbms-cred' 的值必須採用格式 <用戶名>:<密碼>(例如 \"root:pass\")"
        #errMsg += "format <username>:<password> (e.g. \"root:pass\")"
        raise SqlmapSyntaxException(errMsg)

    if conf.encoding:
        _ = checkCharEncoding(conf.encoding, False)
        if _ is None:
            errMsg = "未知的編碼 '%s'。請訪問 '%s' 獲取支持的編碼列表" % (conf.encoding, CODECS_LIST_PAGE)
            #errMsg += "'%s' to get the full list of " % CODECS_LIST_PAGE
            #errMsg += "supported encodings"
            raise SqlmapSyntaxException(errMsg)
        else:
            conf.encoding = _

    if conf.fileWrite and not os.path.isfile(conf.fileWrite):
        errMsg = "file '%s' does not exist" % os.path.abspath(conf.fileWrite)
        raise SqlmapFilePathException(errMsg)

    if conf.loadCookies and not os.path.exists(conf.loadCookies):
        errMsg = "cookies file '%s' does not exist" % os.path.abspath(conf.loadCookies)
        raise SqlmapFilePathException(errMsg)

def initOptions(inputOptions=AttribDict(), overrideOptions=False):
    _setConfAttributes()
    _setKnowledgeBaseAttributes()
    _mergeOptions(inputOptions, overrideOptions)

def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """

    _useWizardInterface()
    setVerbosity()
    _saveConfig()
    _setRequestFromFile()
    _cleanupOptions()
    _cleanupEnvironment()
    _purge()
    _checkDependencies()
    _createHomeDirectories()
    _createTemporaryDirectory()
    _basicOptionValidation()
    _setProxyList()
    _setTorProxySettings()
    _setDNSServer()
    _adjustLoggingFormatter()
    _setMultipleTargets()
    _listTamperingFunctions()
    _setTamperingFunctions()
    _setPreprocessFunctions()
    _setPostprocessFunctions()
    _setTrafficOutputFP()
    _setupHTTPCollector()
    _setHttpChunked()
    _checkWebSocket()

    parseTargetDirect()

    if any((conf.url, conf.logFile, conf.bulkFile, conf.requestFile, conf.googleDork, conf.stdinPipe)):
        _setHostname()
        _setHTTPTimeout()
        _setHTTPExtraHeaders()
        _setHTTPCookies()
        _setHTTPReferer()
        _setHTTPHost()
        _setHTTPUserAgent()
        _setHTTPAuthentication()
        _setHTTPHandlers()
        _setDNSCache()
        _setSocketPreConnect()
        _setSafeVisit()
        _doSearch()
        _setStdinPipeTargets()
        _setBulkMultipleTargets()
        _checkTor()
        _setCrawler()
        _findPageForms()
        _setDBMS()
        _setTechnique()

    _setThreads()
    _setOS()
    _setWriteFile()
    _setMetasploit()
    _setDBMSAuthentication()
    loadBoundaries()
    loadPayloads()
    _setPrefixSuffix()
    update()
    _loadQueries()
