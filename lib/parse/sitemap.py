#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import readInput
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.exception import SqlmapSyntaxException
from lib.request.connect import Connect as Request
from thirdparty.six.moves import http_client as _http_client

abortedFlag = None

def parseSitemap(url, retVal=None):
    global abortedFlag

    if retVal is not None:
        logger.debug("解析站點地圖 '%s'" % url)

    try:
        if retVal is None:
            abortedFlag = False
            retVal = OrderedSet()

        try:
            content = Request.getPage(url=url, raise404=True)[0] if not abortedFlag else ""
        except _http_client.InvalidURL:
            errMsg = "提供的站點地圖 URL 無效 ('%s')" % url
            raise SqlmapSyntaxException(errMsg)

        for match in re.finditer(r"<loc>\s*([^<]+)", content or ""):
            if abortedFlag:
                break
            url = match.group(1).strip()
            if url.endswith(".xml") and "sitemap" in url.lower():
                if kb.followSitemapRecursion is None:
                    message = "檢測到網站地圖遞歸。你想要跟隨嗎？[y/N] "
                    kb.followSitemapRecursion = readInput(message, default='N', boolean=True)
                if kb.followSitemapRecursion:
                    parseSitemap(url, retVal)
            else:
                retVal.add(url)

    except KeyboardInterrupt:
        abortedFlag = True
        warnMsg = "用戶在站點地圖解析過程中中止。sqlmap 將使用部分列表"
        #warnMsg += "will use partial list"
        logger.warning(warnMsg)

    return retVal
