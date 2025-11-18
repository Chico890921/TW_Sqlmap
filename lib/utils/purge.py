#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import functools
import os
import random
import shutil
import stat
import string

from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import logger
from thirdparty.six import unichr as _unichr

def purge(directory):
    """
    Safely removes content from a given directory
    """

    if not os.path.isdir(directory):
        warnMsg = "跳過清理目錄 '%s',因為它不存在" % directory
        logger.warning(warnMsg)
        return

    infoMsg = "清理目錄 '%s' 的內容..." % directory
    logger.info(infoMsg)

    filepaths = []
    dirpaths = []

    for rootpath, directories, filenames in os.walk(directory):
        dirpaths.extend(os.path.abspath(os.path.join(rootpath, _)) for _ in directories)
        filepaths.extend(os.path.abspath(os.path.join(rootpath, _)) for _ in filenames)

    logger.debug("正在更改文件屬性")
    for filepath in filepaths:
        try:
            os.chmod(filepath, stat.S_IREAD | stat.S_IWRITE)
        except:
            pass

    logger.debug("向文件寫入隨機數據")
    for filepath in filepaths:
        try:
            filesize = os.path.getsize(filepath)
            with openFile(filepath, "w+b") as f:
                f.write("".join(_unichr(random.randint(0, 255)) for _ in xrange(filesize)))
        except:
            pass

    logger.debug("正在截斷文件")
    for filepath in filepaths:
        try:
            with open(filepath, 'w') as f:
                pass
        except:
            pass

    logger.debug("將文件名重命名為隨機值")
    for filepath in filepaths:
        try:
            os.rename(filepath, os.path.join(os.path.dirname(filepath), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
        except:
            pass

    dirpaths.sort(key=functools.cmp_to_key(lambda x, y: y.count(os.path.sep) - x.count(os.path.sep)))

    logger.debug("將目錄名重命名為隨機值")
    for dirpath in dirpaths:
        try:
            os.rename(dirpath, os.path.join(os.path.dirname(dirpath), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
        except:
            pass

    logger.debug("刪除整個目錄樹")
    try:
        shutil.rmtree(directory)
    except OSError as ex:
        logger.error("刪除目錄 '%s' 時發生問題 ('%s')" % (getUnicode(directory), getSafeExString(ex)))
