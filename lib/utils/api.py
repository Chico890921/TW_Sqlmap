#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import contextlib
import logging
import os
import re
import shlex
import socket
import sqlite3
import sys
import tempfile
import threading
import time

from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.common import saveConfig
from lib.core.common import setColor
from lib.core.common import unArrayizeValue
from lib.core.compat import xrange
from lib.core.convert import decodeBase64
from lib.core.convert import dejsonize
from lib.core.convert import encodeBase64
from lib.core.convert import encodeHex
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import jsonize
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.datatype import AttribDict
from lib.core.defaults import _defaults
from lib.core.dicts import PART_RUN_CONTENT_TYPES
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import CONTENT_STATUS
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapConnectionException
from lib.core.log import LOGGER_HANDLER
from lib.core.optiondict import optDict
from lib.core.settings import IS_WIN
from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
from lib.core.settings import RESTAPI_DEFAULT_PORT
from lib.core.settings import RESTAPI_UNSUPPORTED_OPTIONS
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.subprocessng import Popen
from lib.parse.cmdline import cmdLineParser
from thirdparty.bottle.bottle import error as return_error
from thirdparty.bottle.bottle import get
from thirdparty.bottle.bottle import hook
from thirdparty.bottle.bottle import post
from thirdparty.bottle.bottle import request
from thirdparty.bottle.bottle import response
from thirdparty.bottle.bottle import run
from thirdparty.bottle.bottle import server_names
from thirdparty import six
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import input as _input
from thirdparty.six.moves import urllib as _urllib

# Global data storage
class DataStore(object):
    admin_token = ""
    current_db = None
    tasks = dict()
    username = None
    password = None

# API objects
class Database(object):
    filepath = None

    def __init__(self, database=None):
        self.database = self.filepath if database is None else database
        self.connection = None
        self.cursor = None

    def connect(self, who="server"):
        self.connection = sqlite3.connect(self.database, timeout=3, isolation_level=None, check_same_thread=False)
        self.cursor = self.connection.cursor()
        self.lock = threading.Lock()
        logger.debug("REST-JSON API %s 已連接到 IPC 數據庫" % who)

    def disconnect(self):
        if self.cursor:
            self.cursor.close()

        if self.connection:
            self.connection.close()

    def commit(self):
        self.connection.commit()

    def execute(self, statement, arguments=None):
        with self.lock:
            while True:
                try:
                    if arguments:
                        self.cursor.execute(statement, arguments)
                    else:
                        self.cursor.execute(statement)
                except sqlite3.OperationalError as ex:
                    if "locked" not in getSafeExString(ex):
                        raise
                    else:
                        time.sleep(1)
                else:
                    break

        if statement.lstrip().upper().startswith("SELECT"):
            return self.cursor.fetchall()

    def init(self):
        self.execute("CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, time TEXT, level TEXT, message TEXT)")
        self.execute("CREATE TABLE IF NOT EXISTS data(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, status INTEGER, content_type INTEGER, value TEXT)")
        self.execute("CREATE TABLE IF NOT EXISTS errors(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, error TEXT)")

class Task(object):
    def __init__(self, taskid, remote_addr):
        self.remote_addr = remote_addr
        self.process = None
        self.output_directory = None
        self.options = None
        self._original_options = None
        self.initialize_options(taskid)

    def initialize_options(self, taskid):
        datatype = {"boolean": False, "string": None, "integer": None, "float": None}
        self.options = AttribDict()

        for _ in optDict:
            for name, type_ in optDict[_].items():
                type_ = unArrayizeValue(type_)
                self.options[name] = _defaults.get(name, datatype[type_])

        # Let sqlmap engine knows it is getting called by the API,
        # the task ID and the file path of the IPC database
        self.options.api = True
        self.options.taskid = taskid
        self.options.database = Database.filepath

        # Enforce batch mode and disable coloring and ETA
        self.options.batch = True
        self.options.disableColoring = True
        self.options.eta = False

        self._original_options = AttribDict(self.options)

    def set_option(self, option, value):
        self.options[option] = value

    def get_option(self, option):
        return self.options[option]

    def get_options(self):
        return self.options

    def reset_options(self):
        self.options = AttribDict(self._original_options)

    def engine_start(self):
        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG, text=True)
        os.close(handle)
        saveConfig(self.options, configFile)

        if os.path.exists("sqlmap.py"):
            self.process = Popen([sys.executable or "python", "sqlmap.py", "--api", "-c", configFile], shell=False, close_fds=not IS_WIN)
        elif os.path.exists(os.path.join(os.getcwd(), "sqlmap.py")):
            self.process = Popen([sys.executable or "python", "sqlmap.py", "--api", "-c", configFile], shell=False, cwd=os.getcwd(), close_fds=not IS_WIN)
        elif os.path.exists(os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "sqlmap.py")):
            self.process = Popen([sys.executable or "python", "sqlmap.py", "--api", "-c", configFile], shell=False, cwd=os.path.join(os.path.abspath(os.path.dirname(sys.argv[0]))), close_fds=not IS_WIN)
        else:
            self.process = Popen(["sqlmap", "--api", "-c", configFile], shell=False, close_fds=not IS_WIN)

    def engine_stop(self):
        if self.process:
            self.process.terminate()
            return self.process.wait()
        else:
            return None

    def engine_process(self):
        return self.process

    def engine_kill(self):
        if self.process:
            try:
                self.process.kill()
                return self.process.wait()
            except:
                pass
        return None

    def engine_get_id(self):
        if self.process:
            return self.process.pid
        else:
            return None

    def engine_get_returncode(self):
        if self.process:
            self.process.poll()
            return self.process.returncode
        else:
            return None

    def engine_has_terminated(self):
        return isinstance(self.engine_get_returncode(), int)

# Wrapper functions for sqlmap engine
class StdDbOut(object):
    def __init__(self, taskid, messagetype="stdout"):
        # Overwrite system standard output and standard error to write
        # to an IPC database
        self.messagetype = messagetype
        self.taskid = taskid

        if self.messagetype == "stdout":
            sys.stdout = self
        else:
            sys.stderr = self

    def write(self, value, status=CONTENT_STATUS.IN_PROGRESS, content_type=None):
        if self.messagetype == "stdout":
            if content_type is None:
                if kb.partRun is not None:
                    content_type = PART_RUN_CONTENT_TYPES.get(kb.partRun)
                else:
                    # Ignore all non-relevant messages
                    return

            output = conf.databaseCursor.execute("SELECT id, status, value FROM data WHERE taskid = ? AND content_type = ?", (self.taskid, content_type))

            # Delete partial output from IPC database if we have got a complete output
            if status == CONTENT_STATUS.COMPLETE:
                if len(output) > 0:
                    for index in xrange(len(output)):
                        conf.databaseCursor.execute("DELETE FROM data WHERE id = ?", (output[index][0],))

                conf.databaseCursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)", (self.taskid, status, content_type, jsonize(value)))
                if kb.partRun:
                    kb.partRun = None

            elif status == CONTENT_STATUS.IN_PROGRESS:
                if len(output) == 0:
                    conf.databaseCursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)", (self.taskid, status, content_type, jsonize(value)))
                else:
                    new_value = "%s%s" % (dejsonize(output[0][2]), value)
                    conf.databaseCursor.execute("UPDATE data SET value = ? WHERE id = ?", (jsonize(new_value), output[0][0]))
        else:
            conf.databaseCursor.execute("INSERT INTO errors VALUES(NULL, ?, ?)", (self.taskid, str(value) if value else ""))

    def flush(self):
        pass

    def close(self):
        pass

    def seek(self):
        pass

class LogRecorder(logging.StreamHandler):
    def emit(self, record):
        """
        Record emitted events to IPC database for asynchronous I/O
        communication with the parent process
        """
        conf.databaseCursor.execute("INSERT INTO logs VALUES(NULL, ?, ?, ?, ?)", (conf.taskid, time.strftime("%X"), record.levelname, str(record.msg % record.args if record.args else record.msg)))

def setRestAPILog():
    if conf.api:
        try:
            conf.databaseCursor = Database(conf.database)
            conf.databaseCursor.connect("client")
        except sqlite3.OperationalError as ex:
            raise SqlmapConnectionException("%s ('%s')" % (ex, conf.database))

        # Set a logging handler that writes log messages to a IPC database
        logger.removeHandler(LOGGER_HANDLER)
        LOGGER_RECORDER = LogRecorder()
        logger.addHandler(LOGGER_RECORDER)

# Generic functions
def is_admin(token):
    return DataStore.admin_token == token

@hook('before_request')
def check_authentication():
    if not any((DataStore.username, DataStore.password)):
        return

    authorization = request.headers.get("Authorization", "")
    match = re.search(r"(?i)\ABasic\s+([^\s]+)", authorization)

    if not match:
        request.environ["PATH_INFO"] = "/error/401"

    try:
        creds = decodeBase64(match.group(1), binary=False)
    except:
        request.environ["PATH_INFO"] = "/error/401"
    else:
        if creds.count(':') != 1:
            request.environ["PATH_INFO"] = "/error/401"
        else:
            username, password = creds.split(':')
            if username.strip() != (DataStore.username or "") or password.strip() != (DataStore.password or ""):
                request.environ["PATH_INFO"] = "/error/401"

@hook("after_request")
def security_headers(json_header=True):
    """
    Set some headers across all HTTP responses
    """
    response.headers["Server"] = "Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"

    if json_header:
        response.content_type = "application/json; charset=UTF-8"

##############################
# HTTP Status Code functions #
##############################

@return_error(401)  # Access Denied
def error401(error=None):
    security_headers(False)
    return "Access denied"

@return_error(404)  # Not Found
def error404(error=None):
    security_headers(False)
    return "Nothing here"

@return_error(405)  # Method Not Allowed (e.g. when requesting a POST method via GET)
def error405(error=None):
    security_headers(False)
    return "Method not allowed"

@return_error(500)  # Internal Server Error
def error500(error=None):
    security_headers(False)
    return "Internal server error"

#############
# Auxiliary #
#############

@get('/error/401')
def path_401():
    response.status = 401
    return response

#############################
# Task management functions #
#############################

# Users' methods
@get("/task/new")
def task_new():
    """
    Create a new task
    """
    taskid = encodeHex(os.urandom(8), binary=False)
    remote_addr = request.remote_addr

    DataStore.tasks[taskid] = Task(taskid, remote_addr)

    logger.debug("創建了新任務:'%s'" % taskid)
    return jsonize({"success": True, "taskid": taskid})

@get("/task/<taskid>/delete")
def task_delete(taskid):
    """
    Delete an existing task
    """
    if taskid in DataStore.tasks:
        DataStore.tasks.pop(taskid)

        logger.debug("(%s) 已刪除任務" % taskid)
        return jsonize({"success": True})
    else:
        response.status = 404
        logger.warning("[%s] 提供給 task_delete() 的任務 ID 不存在" % taskid)
        return jsonize({"success": False, "message": "不存在任務 ID"})

###################
# Admin functions #
###################

@get("/admin/list")
@get("/admin/<token>/list")
def task_list(token=None):
    """
    Pull task list
    """
    tasks = {}

    for key in DataStore.tasks:
        if is_admin(token) or DataStore.tasks[key].remote_addr == request.remote_addr:
            tasks[key] = dejsonize(scan_status(key))["status"]

    logger.debug("(%s) 列出任務池 (%s)" % (token, "管理員" if is_admin(token) else request.remote_addr))
    return jsonize({"success": True, "tasks": tasks, "tasks_num": len(tasks)})

@get("/admin/flush")
@get("/admin/<token>/flush")
def task_flush(token=None):
    """
    Flush task spool (delete all tasks)
    """

    for key in list(DataStore.tasks):
        if is_admin(token) or DataStore.tasks[key].remote_addr == request.remote_addr:
            DataStore.tasks[key].engine_kill()
            del DataStore.tasks[key]

    logger.debug("(%s) 清空任務池 (%s)" % (token, "管理員" if is_admin(token) else request.remote_addr))
    return jsonize({"success": True})

##################################
# sqlmap core interact functions #
##################################

# Handle task's options
@get("/option/<taskid>/list")
def option_list(taskid):
    """
    List options for a certain task ID
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 option_list() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    logger.debug("(%s) 列出任務選項" % taskid)
    return jsonize({"success": True, "options": DataStore.tasks[taskid].get_options()})

@post("/option/<taskid>/get")
def option_get(taskid):
    """
    Get value of option(s) for a certain task ID
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 option_get() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    options = request.json or []
    results = {}

    for option in options:
        if option in DataStore.tasks[taskid].options:
            results[option] = DataStore.tasks[taskid].options[option]
        else:
            logger.debug("(%s) 請求了未知選項 '%s' 的值" % (taskid, option))
            return jsonize({"success": False, "message": "Unknown option '%s'" % option})

    logger.debug("(%s) 檢索到選項的值為'%s'" % (taskid, ','.join(options)))

    return jsonize({"success": True, "options": results})

@post("/option/<taskid>/set")
def option_set(taskid):
    """
    Set value of option(s) for a certain task ID
    """

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 option_set() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    if request.json is None:
        logger.warning("[%s] 提供給 option_set() 的 JSON 選項無效" % taskid)
        return jsonize({"success": False, "message": "無效的 JSON 選項"})

    for option, value in request.json.items():
        DataStore.tasks[taskid].set_option(option, value)

    logger.debug("(%s) 請求設置選項" % taskid)
    return jsonize({"success": True})

# Handle scans
@post("/scan/<taskid>/start")
def scan_start(taskid):
    """
    Launch a scan
    """

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 scan_start() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    if request.json is None:
        logger.warning("[%s] 提供給 scan_start() 的 JSON 選項無效" % taskid)
        return jsonize({"success": False, "message": "無效的 JSON 選項"})

    for key in request.json:
        if key in RESTAPI_UNSUPPORTED_OPTIONS:
            logger.warning("[%s] 提供給 scan_start() 的不支持的選項 '%s'" % (taskid, key))
            return jsonize({"success": False, "message": "不支持的選項 '%s'" % key})

    # Initialize sqlmap engine's options with user's provided options, if any
    for option, value in request.json.items():
        DataStore.tasks[taskid].set_option(option, value)

    # Launch sqlmap engine in a separate process
    DataStore.tasks[taskid].engine_start()

    logger.debug("(%s) 開始掃描" % taskid)
    return jsonize({"success": True, "engineid": DataStore.tasks[taskid].engine_get_id()})

@get("/scan/<taskid>/stop")
def scan_stop(taskid):
    """
    Stop a scan
    """

    if (taskid not in DataStore.tasks or DataStore.tasks[taskid].engine_process() is None or DataStore.tasks[taskid].engine_has_terminated()):
        logger.warning("[%s] 提供給 scan_stop() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    DataStore.tasks[taskid].engine_stop()

    logger.debug("(%s) 停止掃描" % taskid)
    return jsonize({"success": True})

@get("/scan/<taskid>/kill")
def scan_kill(taskid):
    """
    Kill a scan
    """

    if (taskid not in DataStore.tasks or DataStore.tasks[taskid].engine_process() is None or DataStore.tasks[taskid].engine_has_terminated()):
        logger.warning("[%s] 提供給 scan_kill() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    DataStore.tasks[taskid].engine_kill()

    logger.debug("(%s) 終止掃描" % taskid)
    return jsonize({"success": True})

@get("/scan/<taskid>/status")
def scan_status(taskid):
    """
    Returns status of a scan
    """

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 scan_status() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    if DataStore.tasks[taskid].engine_process() is None:
        status = "not running"
    else:
        status = "terminated" if DataStore.tasks[taskid].engine_has_terminated() is True else "running"

    logger.debug("(%s) 檢索到掃描狀態" % taskid)
    return jsonize({
        "success": True,
        "status": status,
        "returncode": DataStore.tasks[taskid].engine_get_returncode()
    })

@get("/scan/<taskid>/data")
def scan_data(taskid):
    """
    Retrieve the data of a scan
    """

    json_data_message = list()
    json_errors_message = list()

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 scan_data() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    # Read all data from the IPC database for the taskid
    for status, content_type, value in DataStore.current_db.execute("SELECT status, content_type, value FROM data WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_data_message.append({"status": status, "type": content_type, "value": dejsonize(value)})

    # Read all error messages from the IPC database
    for error in DataStore.current_db.execute("SELECT error FROM errors WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_errors_message.append(error)

    logger.debug("(%s) 檢索到掃描數據和錯誤消息" % taskid)
    return jsonize({"success": True, "data": json_data_message, "error": json_errors_message})

# Functions to handle scans' logs
@get("/scan/<taskid>/log/<start>/<end>")
def scan_log_limited(taskid, start, end):
    """
    Retrieve a subset of log messages
    """

    json_log_messages = list()

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 scan_log_limited() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    if not start.isdigit() or not end.isdigit() or int(end) < int(start):
        logger.warning("[%s] 提供給 scan_log_limited() 的開始或結束值無效" % taskid)
        return jsonize({"success": False, "message": "無效的開始或結束值,必須為數字"})

    start = max(1, int(start))
    end = max(1, int(end))

    # Read a subset of log messages from the IPC database
    for time_, level, message in DataStore.current_db.execute("SELECT time, level, message FROM logs WHERE taskid = ? AND id >= ? AND id <= ? ORDER BY id ASC", (taskid, start, end)):
        json_log_messages.append({"time": time_, "level": level, "message": message})

    logger.debug("(%s) 檢索到掃描日誌消息子集" % taskid)
    return jsonize({"success": True, "log": json_log_messages})

@get("/scan/<taskid>/log")
def scan_log(taskid):
    """
    Retrieve the log messages
    """

    json_log_messages = list()

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 scan_log() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    # Read all log messages from the IPC database
    for time_, level, message in DataStore.current_db.execute("SELECT time, level, message FROM logs WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_log_messages.append({"time": time_, "level": level, "message": message})

    logger.debug("(%s) 檢索到掃描日誌消息" % taskid)
    return jsonize({"success": True, "log": json_log_messages})

# Function to handle files inside the output directory
@get("/download/<taskid>/<target>/<filename:path>")
def download(taskid, target, filename):
    """
    Download a certain file from the file system
    """

    if taskid not in DataStore.tasks:
        logger.warning("[%s] 提供給 download() 的任務 ID 無效" % taskid)
        return jsonize({"success": False, "message": "無效的任務 ID"})

    path = os.path.abspath(os.path.join(paths.SQLMAP_OUTPUT_PATH, target, filename))
    # 防止文件路徑遍歷
    if not path.startswith(paths.SQLMAP_OUTPUT_PATH):
        logger.warning("[%s] 禁止訪問路徑 (%s)" % (taskid, target))
        return jsonize({"success": False, "message": "禁止訪問路徑"})

    if os.path.isfile(path):
        logger.debug("(%s) 檢索到文件%s 的內容" % (taskid, target))
        content = openFile(path, "rb").read()
        return jsonize({"success": True, "file": encodeBase64(content, binary=False)})
    else:
        logger.warning("[%s] 文件%s 不存在" % (taskid, target))
        return jsonize({"success": False, "message": "文件不存在"})

@get("/version")
def version(token=None):
    """
    Fetch server version
    """

    logger.debug("獲取版本信息 (%s)" % ("admin" if is_admin(token) else request.remote_addr))
    return jsonize({"success": True, "version": VERSION_STRING.split('/')[-1]})

def server(host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT, adapter=RESTAPI_DEFAULT_ADAPTER, username=None, password=None, database=None):
    """
    REST-JSON API server
    """

    DataStore.admin_token = encodeHex(os.urandom(16), binary=False)
    DataStore.username = username
    DataStore.password = password

    if not database:
        _, Database.filepath = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.IPC, text=False)
        os.close(_)
    else:
        Database.filepath = database

    if port == 0:  # random
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind((host, 0))
            port = s.getsockname()[1]

    logger.info("正在運行 REST-JSON API 服務器,地址為 '%s:%d'.." % (host, port))
    logger.info("管理員 (祕密) 令牌:%s" % DataStore.admin_token)
    logger.debug("IPC 數據庫:'%s'" % Database.filepath)

    # Initialize IPC database
    DataStore.current_db = Database()
    DataStore.current_db.connect()
    DataStore.current_db.init()

    # Run RESTful API
    try:
        # Supported adapters: aiohttp, auto, bjoern, cgi, cherrypy, diesel, eventlet, fapws3, flup, gae, gevent, geventSocketIO, gunicorn, meinheld, paste, rocket, tornado, twisted, waitress, wsgiref
        # Reference: https://bottlepy.org/docs/dev/deployment.html || bottle.server_names

        if adapter == "gevent":
            from gevent import monkey
            monkey.patch_all()
        elif adapter == "eventlet":
            import eventlet
            eventlet.monkey_patch()
        logger.debug("使用適配器 '%s' 運行 Bottle" % adapter)
        run(host=host, port=port, quiet=True, debug=True, server=adapter)
    except socket.error as ex:
        if "already in use" in getSafeExString(ex):
            logger.error("地址已被佔用 ('%s:%s')" % (host, port))
        else:
            raise
    except ImportError:
        if adapter.lower() not in server_names:
            errMsg = "適配器 '%s' 未知。" % adapter
            errMsg += "支持的適配器列表:%s" % ', '.join(sorted(list(server_names.keys())))
        else:
            errMsg = "此係統上未安裝適配器 '%s' 的服務器支持 " % adapter
            errMsg += "(注意:您可以嘗試使用 'apt install python-%s' 或 'pip%s install %s' 安裝它)" % (adapter, '3' if six.PY3 else "", adapter)
        logger.critical(errMsg)

def _client(url, options=None):
    logger.debug("調用 '%s'" % url)
    try:
        headers = {"Content-Type": "application/json"}

        if options is not None:
            data = getBytes(jsonize(options))
        else:
            data = None

        if DataStore.username or DataStore.password:
            headers["Authorization"] = "Basic %s" % encodeBase64("%s:%s" % (DataStore.username or "", DataStore.password or ""), binary=False)

        req = _urllib.request.Request(url, data, headers)
        response = _urllib.request.urlopen(req)
        text = getText(response.read())
    except:
        if options:
            logger.error("無法加載和解析 %s" % url)
        raise
    return text

def client(host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT, username=None, password=None):
    """
    REST-JSON API client
    """

    DataStore.username = username
    DataStore.password = password

    dbgMsg = "從命令行訪問示例客戶端:"
    dbgMsg += "\n\t$ taskid=$(curl http://%s:%d/task/new 2>1 | grep -o -I '[a-f0-9]\\{16\\}') && echo $taskid" % (host, port)
    dbgMsg += "\n\t$ curl -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' http://%s:%d/scan/$taskid/start" % (host, port)
    dbgMsg += "\n\t$ curl http://%s:%d/scan/$taskid/data" % (host, port)
    dbgMsg += "\n\t$ curl http://%s:%d/scan/$taskid/log" % (host, port)
    logger.debug(dbgMsg)

    addr = "http://%s:%d" % (host, port)
    logger.info("正在啟動 REST-JSON API 客戶端到 '%s'..." % addr)

    try:
        _client(addr)
    except Exception as ex:
        if not isinstance(ex, _urllib.error.HTTPError) or ex.code == _http_client.UNAUTHORIZED:
            errMsg = "連接到 REST-JSON API 服務器 '%s' 時出現問題 " % addr
            #errMsg += "REST-JSON API server at '%s' " % addr
            errMsg += "(%s)" % getSafeExString(ex)
            logger.critical(errMsg)
            return

    commands = ("help", "new", "use", "data", "log", "status", "option", "stop", "kill", "list", "flush", "version", "exit", "bye", "quit")
    colors = ('red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'lightgrey', 'lightred', 'lightgreen', 'lightyellow', 'lightblue', 'lightmagenta', 'lightcyan')
    autoCompletion(AUTOCOMPLETE_TYPE.API, commands=commands)

    taskid = None
    logger.info("輸入 'help' 或 '?' 獲取可用命令列表")

    while True:
        try:
            color = colors[int(taskid or "0", 16) % len(colors)]
            command = _input("api%s> " % (" (%s)" % setColor(taskid, color) if taskid else "")).strip()
            command = re.sub(r"\A(\w+)", lambda match: match.group(1).lower(), command)
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if command in ("data", "log", "status", "stop", "kill"):
            if not taskid:
                logger.error("未使用任務 ID")
                continue
            raw = _client("%s/scan/%s/%s" % (addr, taskid, command))
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("無法執行命令 %s" % command)
            dataToStdout("%s\n" % raw)

        elif command.startswith("option"):
            if not taskid:
                logger.error("未使用任務 ID")
                continue
            try:
                command, option = command.split(" ", 1)
            except ValueError:
                raw = _client("%s/option/%s/list" % (addr, taskid))
            else:
                options = re.split(r"\s*,\s*", option.strip())
                raw = _client("%s/option/%s/get" % (addr, taskid), options)
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("無法執行命令 %s" % command)
            dataToStdout("%s\n" % raw)

        elif command.startswith("new"):
            if ' ' not in command:
                logger.error("缺少程序參數")
                continue

            try:
                argv = ["sqlmap.py"] + shlex.split(command)[1:]
            except Exception as ex:
                logger.error("解析參數時發生錯誤 ('%s')" % getSafeExString(ex))
                taskid = None
                continue

            try:
                cmdLineOptions = cmdLineParser(argv).__dict__
            except:
                taskid = None
                continue

            for key in list(cmdLineOptions):
                if cmdLineOptions[key] is None:
                    del cmdLineOptions[key]

            raw = _client("%s/task/new" % addr)
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("創建新任務失敗 ('%s')" % res.get("message", ""))
                continue
            taskid = res["taskid"]
            logger.info("新任務 ID 為 '%s'" % taskid)

            raw = _client("%s/scan/%s/start" % (addr, taskid), cmdLineOptions)
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("啟動掃描失敗 ('%s')" % res.get("message", ""))
                continue
            logger.info("掃描已開始")

        elif command.startswith("use"):
            taskid = (command.split()[1] if ' ' in command else "").strip("'\"")
            if not taskid:
                logger.error("任務 ID 丟失")
                taskid = None
                continue
            elif not re.search(r"\A[0-9a-fA-F]{16}\Z", taskid):
                logger.error("無效的任務 ID('%s')" % taskid)
                taskid = None
                continue
            logger.info("切換到任務 ID '%s'" % taskid)

        elif command in ("version",):
            raw = _client("%s/%s" % (addr, command))
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("無法執行命令 %s" % command)
            dataToStdout("%s\n" % raw)

        elif command in ("list", "flush"):
            raw = _client("%s/admin/%s" % (addr, command))
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("無法執行命令 %s" % command)
            elif command == "flush":
                taskid = None
            dataToStdout("%s\n" % raw)

        elif command in ("exit", "bye", "quit", 'q'):
            return

        elif command in ("help", "?"):
            msg = "help           顯示此幫助消息\n"
            msg += "new ARGS       使用提供的參數啟動新的掃描任務 (例如 'new -u \"http://testphp.vulnweb.com/artists.php?artist=1\"')\n"
            msg += "use TASKID     切換當前上下文到不同的任務 (例如 'use c04d8c5c7582efb4')\n"
            msg += "data           檢索並顯示當前任務的數據\n"
            msg += "log            檢索並顯示當前任務的日誌\n"
            msg += "status         檢索並顯示當前任務的狀態\n"
            msg += "option OPTION  檢索並顯示當前任務的選項\n"
            msg += "options        檢索並顯示當前任務的所有選項\n"
            msg += "stop           停止當前任務\n"
            msg += "kill           終止當前任務\n"
            msg += "list           顯示所有任務\n"
            msg += "version        獲取服務器版本\n"
            msg += "flush          清空任務 (刪除所有任務)\n"
            msg += "exit           退出客戶端\n"

            dataToStdout(msg)

        elif command:
            logger.error("未知命令 ('%s')" % command)
