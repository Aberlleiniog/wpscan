#!/usr/bin/python3

import time

from core import db, audit

# Initialize
dbCollectionName = "wpscan"

class _wpscan(db._document):
    url = str()
    lastScan = int()
    extensions = str()
    scanResult = dict()
    _dbCollection = db.db[dbCollectionName]

    def new(self, url):
        self.url = url
        return super(_wpscan, self).new()

    def updateRecord(self, url, scanResult, extensions=""):
        audit._audit().add("wpscan","history",{ "lastUpdate" : self.lastUpdateTime, "endDate" : int(time.time()), "url" : self.url, "extensions": extensions, "scanResult" : self.scanResult })
        self.url = url
        self.lastScan = int(time.time())
        self.extensions = extensions
        self.scanResult = scanResult
        self.update(["lastScan","url", "extensions", "scanResult"])

    def restoreFromQuery(self, query, skip=0):
        queryRet = self.query(query=query, limit=1, sort=[("lastScan", -1)], skip=skip)['results']
        if len(queryRet) == 0:
            return None
        state = queryRet[0]
        self.url = state['url']
        self.lastScan = state['lastScan']
        self.extensions = state['extensions']
        self.scanResult = state['scanResult']
        return self