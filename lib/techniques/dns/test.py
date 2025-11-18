#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.exception import SqlmapNotVulnerableException
from lib.techniques.dns.use import dnsUse

def dnsTest(payload):
    logger.info("通過 DNS 信道進行數據檢索測試")

    randInt = randomInt()
    kb.dnsTest = dnsUse(payload, "SELECT %d%s" % (randInt, FROM_DUMMY_TABLE.get(Backend.getIdentifiedDbms(), ""))) == str(randInt)

    if not kb.dnsTest:
        errMsg = "通過 DNS 通道進行數據檢索失敗"
        if not conf.forceDns:
            conf.dnsDomain = None
            errMsg += "。關閉 DNS 數據洩露支持"
            logger.error(errMsg)
        else:
            raise SqlmapNotVulnerableException(errMsg)
    else:
        infoMsg = "通過 DNS 通道進行數據檢索成功"
        logger.info(infoMsg)
