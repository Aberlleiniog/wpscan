import json

from core.models import action
from core import helpers
import subprocess
from plugins.wpscan.models import wpscan
from time import time

class _wpscanFresh(action._action):
    wp_url = str()
    run_remote = False
    enum_all_plugins = False
    enum_all_themes = False
    enum_users = True

    def doAction(self, data, wp_url=None, extensions=None):
        if wp_url == None:
            wp_url = helpers.evalString(self.wp_url, {"data": data['flowData']})
        if extensions == None:
            extensions = constructExtensions(self.enum_all_plugins, self.enum_all_themes, self.enum_users)
        if self.run_remote and "remote" in data['eventData']:
            if "client" in data['eventData']["remote"]:
                client = data['eventData']["remote"]["client"]
                stdout,stderr = runWPScan(wp_url, extensions, True, client)
        else:
            stdout,stderr = runWPScan(wp_url, extensions)
        if not stdout:
                return {"result": False, "rc": 500, "msg": stderr}
        results = json.loads(stdout)
        db_obj = wpscan._wpscan()
        scanResult = db_obj.new(wp_url)
        db_obj.updateRecord(wp_url, results, extensions)
        results['timestamp'] = int(time())
        actionResult = {}
        actionResult["result"] = True
        actionResult["rc"] = 200
        actionResult["data"] = results
        return actionResult




class _wpscanCached(action._action):
    wp_url = str()
    if_not_ran_days = str()
    run_remote = False
    enum_all_plugins = False
    enum_all_themes = False
    enum_users = True

    def doAction(self, data):
        wp_url = helpers.evalString(self.wp_url, {"data": data['flowData']})
        time_limit_days = int(helpers.evalString(self.if_not_ran_days, {"data": data['flowData']}))
        time_filter = time() - (time_limit_days * 86400)
        extensions = constructExtensions(self.enum_all_plugins, self.enum_all_themes, self.enum_users)
        previous = retrieveResults(wp_url, time_filter, extensions)
        if previous == None:
            newScan = _wpscanFresh()
            return newScan.doAction(data, wp_url, extensions)
        actionResult = {}
        actionResult["data"] = previous.scanResult
        actionResult["data"]['timestamp'] = previous.lastScan
        actionResult["result"] = True
        actionResult["rc"] = 200
        return actionResult


class _wpscanRetrieve(action._action):
    wp_url = str()
    enum_all_plugins = False
    enum_all_themes = False
    enum_users = True

    def run(self, data, persistentData, actionResult):
        wp_url = helpers.evalString(self.wp_url, {"data": data})
        extensions = constructExtensions(self.enum_all_plugins, self.enum_all_themes, self.enum_users)
        previous = retrieveResults(wp_url, extensions=extensions)
        if previous == None:
            actionResult["result"] = False
            actionResult["rc"] = 404
        else:
            actionResult["data"] = previous.scanResult
            actionResult["data"]['timestamp'] = previous.lastScan
            actionResult["result"] = True
            actionResult["rc"] = 200
        return actionResult



def runWPScan(wp_url, extensions, remote=False, remoteClient=None):
    if remote:
        if remoteClient:
            exitCode, stdout, stderr = remoteClient.command(
                " ".join(["wpscan", "--url", wp_url, "-e", extensions, "-f", "json", "--rua"]),
                elevate=True)
            return stdout,stderr
    else:
        print(wp_url)
        process = subprocess.Popen(
            ["wpscan", "--url", wp_url, "-e", extensions, "-f", "json", "--rua"], shell=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        stdout = stdout.decode()
        stderr = stderr.decode()
        return stdout,stderr

## time_filter in days
def retrieveResults(wp_url, time_filter=0, extensions=None):
    db_obj = wpscan._wpscan()
    query = {"url": wp_url}
    i=0
    previous = db_obj.restoreFromQuery(query, skip=i)
    while previous != None and previous.lastScan > time_filter:
        if extensions == None or extensionsMet(previous.extensions, extensions):
            return previous
        i += 1
        previous = db_obj.restoreFromQuery(query, skip=i)
    return None

all_plugins = 'ap'
vuln_plugins = 'vp'
all_themes = 'at'
vuln_themes = 'vt'
users = 'u'

def constructExtensions(enum_all_plugins = False, enum_all_themes = False, enum_users = False):
    extensions = []
    if enum_all_plugins:
        extensions.append(all_plugins)
    else:
        extensions.append(vuln_plugins)
    if enum_all_themes:
        extensions.append(all_themes)
    else:
        extensions.append(vuln_themes)
    if enum_users:
        extensions.append(users)
    return ','.join(extensions)

def extensionsMet(extensions, requiredExtensions):
    if all_plugins in requiredExtensions:
        if all_plugins not in extensions:
            return False
    if all_themes in requiredExtensions:
        if all_themes not in extensions:
            return False
    if users in requiredExtensions:
        if users not in extensions:
            return False
    return True


