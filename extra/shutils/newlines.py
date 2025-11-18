#! /usr/bin/env python

from __future__ import print_function

import os
import sys

def check(filepath):
    if filepath.endswith(".py"):
        content = open(filepath, "rb").read()
        pattern = "\n\n\n".encode("ascii")

        if pattern in content:
            index = content.find(pattern)
            print(filepath, repr(content[index - 30:index + 30]))

if __name__ == "__main__":
    try:
        BASE_DIRECTORY = sys.argv[1]
    except IndexError:
        print("未指定目錄，默認為當前工作目錄")
        BASE_DIRECTORY = os.getcwd()

    print("在'%s'的子目錄中查找 (全部)*.py 腳本" % BASE_DIRECTORY)
    for root, dirs, files in os.walk(BASE_DIRECTORY):
        if any(_ in root for _ in ("extra", "thirdparty")):
            continue
        for name in files:
            filepath = os.path.join(root, name)
            check(filepath)
