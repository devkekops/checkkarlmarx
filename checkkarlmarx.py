import argparse
import subprocess
import os
import json
from datetime import datetime
from shutil import rmtree
import plistlib
import xml.etree.ElementTree as etree
import re
from xml.dom import minidom
from bs4 import BeautifulSoup
from jinja2 import FileSystemLoader, Environment
from html import escape
from urllib.parse import urlparse
import sarif_om as om
from jschema_to_python.to_json import to_json
import pathlib
from urllib.parse import quote

AAPTPATH = './build-tools/android-10/aapt'
APKTOOL = 'apktool.jar'
MOUNTDIR = '/mount/'

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

APK = 'apk'
ALLOWED_EXTS = ['apk', 'ipa']
ANDROID = "android"
IOS = "ios"
ALL = "all"

FIREBASEDATABASEURL = r'https:\/\/(?:.+?)\.firebaseio.com'
NSANDROIDURI = 'http://schemas.android.com/apk/res/android'
TRUSTANCHORS = b'<trust-anchors'
CLEARTEXTTRAFFICPERMITTED = b'cleartextTrafficPermitted'
DISABLESAFEBROWSING = b'<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false"/>'
NSAPPTRANSPORTSECURITY = 'NSAppTransportSecurity'
NSALLOWSARBITRARYLOADS = 'NSAllowsArbitraryLoads'
NSALLOWSARBITRARYLOADSBIN = b'NSAllowsArbitraryLoads'
NSALLOWSARBITRARYLOADSFORMEDIA = 'NSAllowsArbitraryLoadsForMedia'
NSALLOWSARBITRARYLOADSFORMEDIABIN = b'NSAllowsArbitraryLoadsForMedia'
NSALLOWSARBITRARYLOADSINWEBCONTENT = 'NSAllowsArbitraryLoadsInWebContent'
NSALLOWSARBITRARYLOADSINWEBCONTENTBIN = b'NSAllowsArbitraryLoadsInWebContent'
NSALLOWSLOCALNETWORKING = 'NSAllowsLocalNetworking'
NSALLOWSLOCALNETWORKINGBIN = b'NSAllowsLocalNetworking'
NSEXCEPTIONDOMAINS = 'NSExceptionDomains'
NSEXCEPTIONDOMAINSBIN = b'NSExceptionDomains'

EXTSLIST = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.bmp', '.webp', '.bmp', '.eot', '.otf', '.ttf', '.woff', '.woff2', '.so', '.proto', '.zip']

URLS = rb'(?:http|ws)[s]?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
ANDROIDBLACKLISTURLS = [b'schemas.android.com', b'www.apache.org', b'www.w3.org', b'schema.org',
                 b'www.obj-sys.com', b'ns.adobe.com', b'xml.org', b'xmlpull.org', b'xml.apache.org',
                 b'java.sun.com/', b'www.apple.com/DTDs', b'developer.android.com', b'developers.google.com/', b'developer.mozilla.org',
                        b'www.unicode.org']
IOSBLACKLISTURLS = [b'www.apple.com', b'ocsp.apple.com', b'crl.apple.com', b'ocsp.comodoca.com', b'ns.adobe.com',
                    b'www.apache.org', b'www.w3.org', b'itunes', b'www.webrtc.org', b'www.unicode.org']
BASICAUTH = r'^(?:.+?\/\/)(?:.+?):(?:.+?)@(?:.+)$'
QATAGS = ['qa', 'test', 'dev', 'uat', 'stage']

PRIVATEKEY = b'-----BEGIN (?:EC|PGP|DSA|RSA|OPENSSH)? ?PRIVATE KEY ?(?:BLOCK)?-----'
FCMSERVERKEY = rb'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
GOOGLEAPIKEY = rb'AIzaSy[0-9A-Za-z_-]{33}'

SHOULDOVERRIDEURLLOADING = b'shouldOverrideUrlLoading'
SETALLOWFILEACCESS = b'setAllowFileAccess'
SETJAVASCRIPTENABLED = b'setJavaScriptEnabled'
SETALLOWCONTENTACCESS = b'setAllowContentAccess'
SETALLOWFILEACCESSFROMFILEURLS = b'setAllowFileAccessFromFileURLs'
SETALLOWUNIVERSALACCESSFORMFILEURLS = b'setAllowUniversalAccessFromFileURLs'
ADDJAVASCRIPTINTERFACE = b'addJavascriptInterface'

CHECKS = [{'id': '0', 'name': 'NSC CustomTrustedCAs', 'os': 'android', 'tag': 'network', 'severity': 'Normal', 'info': 'Additional trust anchors in Network Security Config:\n<a target="_blank" href = "https://developer.android.com/training/articles/security-config#manifest">Add a Network Security Configuration file</a>\n<a target="_blank" href="https://developer.android.com/training/articles/security-config#ConfigCustom">Configure a custom CA</a>'},
          {'id': '1', 'name': 'NSC CleartextTraffic', 'os': 'android', 'tag': 'network', 'severity': 'Normal', 'info': 'Allow using the unencrypted HTTP protocol instead of HTTPS in Network Security Config:\n<a target="_blank" href = "https://developer.android.com/training/articles/security-config#manifest">Add a Network Security Configuration file</a>\n<a target="_blank" href = "https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted">Opt out of cleartext traffic</a>'},
          {'id': '2', 'name': 'Exported Activities', 'os': 'android', 'tag': 'components', 'severity': 'Info', 'info': 'Activities exported to other applications'},
          {'id': '3', 'name': 'Exported Receivers', 'os': 'android', 'tag': 'components', 'severity': 'Info', 'info': 'Receivers exported to other applications'},
          {'id': '4', 'name': 'Exported Services', 'os': 'android', 'tag': 'components', 'severity': 'Info', 'info': 'Services exported to other applications'},
          {'id': '5', 'name': 'Exported Providers', 'os': 'android', 'tag': 'components', 'severity': 'Info', 'info': 'Providers exported to other applications'},
          {'id': '6', 'name': 'Disabled SafeBrowsing', 'os': 'android', 'tag': 'webview', 'severity': 'Minor', 'info': 'EnableSafeBrowsing set to "false" in manifest allow open potentially unsafe websites in all WebViews:\n<a target="_blank" href = "https://developer.android.com/guide/webapps/managing-webview#safe-browsing">Google Safe Browsing Service</a>'},

          {'id': '7', 'name': 'NS Allows Arbitrary Loads', 'os': 'ios', 'tag': 'network', 'severity': 'Normal', 'info': 'Disable ATS restrictions globally excepts for individual domains specified under NSExceptionDomains'},
          {'id': '8', 'name': 'NS Allows Arbitrary Loads For Media', 'os': 'ios', 'tag': 'network', 'severity': 'Normal', 'info': 'Disable all ATS restrictions for media loaded through the AV Foundations framework'},
          {'id': '9', 'name': 'NS Allows Arbitrary Loads In Web Content',  'os': 'ios', 'tag': 'network', 'severity': 'Normal', 'info': 'Disable ATS restrictions for all the connections made from web views'},
          {'id': '10', 'name': 'NS Allows Local Networking', 'os': 'ios', 'tag': 'network', 'severity': 'Normal', 'info': 'Allow connection to unqualified domain names and .local domains'},
          {'id': '11', 'name': 'NS Exception Domains', 'os': 'ios', 'tag': 'network', 'severity': 'Normal', 'info': 'NS Exception Domains'},

          {'id': '12', 'name': 'Basic Auth URLs', 'os': 'all', 'tag': 'urls', 'severity':'Major', 'info': 'URLs with basic credentials: https://username:password@example.com'},
          {'id': '13', 'name': 'Http Insecure URLs', 'os': 'all', 'tag': 'urls', 'severity': 'Minor', 'info': 'Http URLs starts with http://'},
          {'id': '14', 'name': 'WS Insecure URLs', 'os': 'all', 'tag': 'urls', 'severity': 'Minor', 'info': 'WebSocket URLs starts with ws://'},
          {'id': '15', 'name': 'QA URLs', 'os': 'all', 'tag': 'urls', 'severity': 'Minor', 'info': 'Http and WebSocket URLs contains qa tags (e.g. qa, test, dev, uat, stage)'},

          {'id': '16', 'name': 'Private Keys', 'os': 'all', 'tag': 'keys', 'severity': 'Major', 'pattern': PRIVATEKEY, 'info': 'Asymmetric Private RSA/EC/DSA/PGP/OPENSSH Keys'},
          {'id': '17', 'name': 'FCM Server Key', 'os': 'all', 'tag': 'keys', 'severity': 'Major', 'pattern': FCMSERVERKEY, 'info': 'Authorization key for FCM SDK: <a target="blank" href="https://abss.me/posts/fcm-takeover/">Firebase Cloud Messaging Service Takeover</a>'}, #example: AAAAODDc_Do:APA91bG5kQSzauxg1GSrq3eot5GUPyfouZ5KZObtBUpdM0xoxWGCulSPK1FIKan3IIBK-YlrkOcXkIo0kv7NlUFSOV54Qdy21z9czkFBoe6dMxBEEKAAD8KlC3LYuDugRdrMXJr1ggsL
          {'id': '18','name': 'Google Api Key', 'os': 'all', 'tag': 'keys', 'severity': 'Info', 'pattern': GOOGLEAPIKEY, 'info': 'Google API Key, Legacy FCM server Key: <a target="blank" href="https://abss.me/posts/fcm-takeover/">Firebase Cloud Messaging Service Takeover</a>'}, #example: AIzaSyDIw1n6tfz8_ANZVXJLRuBQrX-7culIFHM

          {'id': '19', 'name': 'Should Override Url Loadings', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': SHOULDOVERRIDEURLLOADING, 'info': 'Allow open 3rd party links in WebView instead of browser:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebViewClient#shouldOverrideUrlLoading(android.webkit.WebView,%20android.webkit.WebResourceRequest)">shouldOverrideUrlLoading</a>'},
          {'id': '20', 'name': 'Set JavaScript Enabled', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': SETJAVASCRIPTENABLED, 'info': 'Tells the WebView to enable JavaScript execution:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean)">setJavascriptEnabled</a>'},
          {'id': '21', 'name': 'Set Allow File Access', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': SETALLOWFILEACCESS, 'info': 'Enables or disables file access within WebView:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean)">setAllowFileAccess</a>'},
          {'id': '22', 'name': 'Set Allow Content Access', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': SETALLOWCONTENTACCESS, 'info': 'Enables or disables content URL access within WebView:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setAllowContentAccess(boolean)">setAllowContentAccess</a>'},
          {'id': '23', 'name': 'Set Allow File Access From File URLs', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': SETALLOWFILEACCESSFROMFILEURLS, 'info': 'Sets whether cross-origin requests in the context of a file scheme URL should be allowed to access content from other file scheme URLs:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean)">setAllowFileAccessFromFileURLs</a>'},
          {'id': '24', 'name': 'Set Allow Universal Access From File URLs', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': SETALLOWUNIVERSALACCESSFORMFILEURLS, 'info': 'Sets whether cross-origin requests in the context of a file scheme URL should be allowed to access content from any origin:\n<a target="_blank" href = "https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean)">setAllowUniversalAccessFromFileURLs</a>'},
          {'id': '25', 'name': 'Add Javascript Interface', 'os': 'android', 'tag': 'webview', 'severity': 'Info', 'pattern': ADDJAVASCRIPTINTERFACE, 'info': 'Injects the supplied Java object into this WebView:\n<a target="blank" href="https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)">addJavascriptInterface</a>'}
              ]

class Audit:
    def __init__(self, startTime, os, filename, filepath, folderpath, checks, domains=None, packages=None, packageId=None, packageVersion=None, packageCodeVersion=None, firebaseDatabaseUrl = None,
                 time=None, summary=None, nameToIndexMap=None):
        self.startTime = startTime
        self.os = os
        self.filename = filename
        self.filepath = filepath
        self.folderpath = folderpath
        self.checks = checks
        self.domains = domains
        self.packages = packages
        self.packageId = packageId
        self.packageVersion = packageVersion
        self.packageCodeVersion = packageCodeVersion
        self.firebaseDatabaseUrl = firebaseDatabaseUrl
        self.time = time
        self.summary = summary
        self.nameToIndexMap = nameToIndexMap

    def setPackageId(self, value):
        self.packageId = value

    def setPackageVersion(self, value):
        self.packageVersion = value

    def setPackageCodeVersion(self, value):
        self.packageCodeVersion = value

    def setFirebaseDatabaseUrl(self, value):
        self.firebaseDatabaseUrl = value

    def setTime(self, value):
        self.time = value

    def setFoundForName(self, name, found):
        self.checks[self.nameToIndexMap[name]].setFound(found)

    def setProofsForName(self, name, proofs):
        self.checks[self.nameToIndexMap[name]].setProofs(proofs)

class Check:
    def __init__(self, id, name, tag=None, severity=None, pattern=None, found=None, proofs=None, info=None):
        self.id = id
        self.name = name
        self.tag = tag
        self.severity = severity
        self.pattern = pattern
        self.found = found
        self.proofs = proofs
        self.info = info

    def setSeverity(self, value):
        self.severity = value

    def setFound(self, value):
        self.found = value

    def setProofs(self, value):
        self.proofs = value

    def setInfo(self, value):
        self.info = value

    def decodePattern(self):
        if self.pattern:
            self.pattern = self.pattern.decode()

def getExtension(filepath):
    return filepath.rsplit('.', 1)[-1].lower()

def getCleanName(filepath):
    return os.path.split(filepath)[1]

def getNameWithoutExt(filepath):
    return os.path.split(filepath)[1].rsplit('.', 1)[0]

def androidAudit(audit):
    doApktool(audit.filepath, audit.folderpath)

    auditManifest(audit)
    auditResAndroid(audit)

    search(audit)

    rmtree(audit.folderpath)

    endTime = datetime.now()
    auditTime = str(endTime - audit.startTime).split('.')[0]
    audit.setTime(auditTime)

def iosAudit(audit):
    doUnzip(audit.filepath, audit.folderpath)

    auditInfoPlist(audit)
    auditResIos(audit)

    search(audit)

    rmtree(audit.folderpath)

    endTime = datetime.now()
    auditTime = str(endTime - audit.startTime).split('.')[0]
    audit.setTime(auditTime)

def doApktool(filepath, folderpath):
    subprocess.check_call(['java', '-jar', APKTOOL, 'd', '-f', filepath, '-o', folderpath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #popen = subprocess.Popen(['apktool', 'd', '-f', filepath, '-o', folderpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #popen.wait()

def doUnzip(filepath, folderpath):
    subprocess.check_call(['unzip', '-o', filepath, '-d', folderpath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #popen = subprocess.Popen(['unzip', '-o', filepath, '-d', folderpath], stdout=subprocess.PIPE)
    #popen.wait()

def auditManifest(audit):
    folderpath = audit.folderpath
    manifestpath = folderpath + 'AndroidManifest.xml'
    tree = etree.parse(manifestpath)
    root = tree.getroot()
    app = root.find('application')
    appAttrs = app.attrib

    rootAttrs = root.attrib
    if 'package' in rootAttrs:
        audit.setPackageId(rootAttrs['package'])

    #aaptOutput = subprocess.check_output([AAPTPATH, 'dump', 'badging', audit.filepath]).decode()
    p = subprocess.Popen([AAPTPATH, 'dump', 'badging', audit.filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    aaptOutput = p.communicate()[0].decode()
    version = re.findall('versionName=\'([^\s]+)\'', aaptOutput)[0]
    codeVersion = re.findall('versionCode=\'([^\s]+)\'', aaptOutput)[0]
    if version:
        audit.setPackageVersion(version)
    if codeVersion:
        audit.setPackageCodeVersion(codeVersion)

    if '{http://schemas.android.com/apk/res/android}networkSecurityConfig' in appAttrs:
        NSCENTRY = 'android:networkSecurityConfig="' + appAttrs['{http://schemas.android.com/apk/res/android}networkSecurityConfig'] + '"'
        nscEntry = grep(manifestpath, NSCENTRY)
        nscconfigpath = folderpath + 'res/' + appAttrs['{http://schemas.android.com/apk/res/android}networkSecurityConfig'][1:] + '.xml' #android:networkSecurityConfig="@xml/network_security_configuration"

        haveTrustAnchors = False
        with open(nscconfigpath) as fp:
            soup = BeautifulSoup(fp, 'html.parser')
            trustAnchorsTags = soup.find_all('trust-anchors')
            if trustAnchorsTags:
                for tag in trustAnchorsTags:
                    if not tag.find_parents('debug-overrides'):
                        haveTrustAnchors = True

        if haveTrustAnchors:
            trustAnchors = grepBinary(nscconfigpath, TRUSTANCHORS)
            nscconfig = open(nscconfigpath, "r").read()
            audit.setFoundForName('NSC CustomTrustedCAs', 'yes')
            audit.setProofsForName('NSC CustomTrustedCAs', [nscEntry, {nscconfig: list(trustAnchors.values())[0]}]) #json.dumps(nscEntry, sort_keys = True, indent = 4) + '\n' + escape(nscconfig) + ":\n" + nscconfigpath)

        #https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted
        cleartextTraffic = grepBinary(nscconfigpath, CLEARTEXTTRAFFICPERMITTED)
        #print(cleartextTraffic)
        if cleartextTraffic:
            nscconfig = open(nscconfigpath, "r").read()
            audit.setFoundForName('NSC CleartextTraffic', 'yes')
            audit.setProofsForName('NSC CleartextTraffic', [nscEntry, {nscconfig: list(cleartextTraffic.values())[0]}]) #json.dumps(nscEntry, sort_keys = True, indent = 4) + '\n' + escape(nscconfig) + ":\n" + nscconfigpath)

    appMetaDatas = app.findall('meta-data')
    disableSafeBrowsing = False
    for appMetaData in appMetaDatas:
        if appMetaData.attrib['{http://schemas.android.com/apk/res/android}name'] == 'android.webkit.WebView.EnableSafeBrowsing':
            if appMetaData.attrib['{http://schemas.android.com/apk/res/android}value'] == 'false':
                disableSafeBrowsing = True
                break

    if disableSafeBrowsing:
        disableSafeBrowsingEntry = grepBinary(manifestpath, DISABLESAFEBROWSING)
        audit.setFoundForName('Disabled SafeBrowsing', 'yes')
        audit.setProofsForName('Disabled SafeBrowsing', disableSafeBrowsingEntry)

    expComps = getExportedComponents(manifestpath)
    #print(expComps)

    with open(manifestpath) as mp:
        soup = BeautifulSoup(mp, 'html.parser')

    if expComps['activity'] or expComps['activity-alias']:
        proofs = {}
        if expComps['activity']:
            for activityName in expComps['activity']:
                tag = soup.find('activity', {"android:name": activityName})
                proofs[tag.prettify()] = list(grep(manifestpath, activityName).values())[0]
        if expComps['activity-alias']:
            for activityAliasName in expComps['activity']:
                tag = soup.find('activity', {"android:name": activityAliasName})
                proofs[tag.prettify()] = list(grep(manifestpath, activityAliasName).values())[0]

        audit.setFoundForName('Exported Activities', 'yes')
        audit.setProofsForName('Exported Activities', proofs)

    if expComps['receiver']:
        proofs = {}
        for receiverName in expComps['receiver']:
            tag = soup.find('receiver', {"android:name": receiverName})
            proofs[tag.prettify()] = list(grep(manifestpath, receiverName).values())[0]

        audit.setFoundForName('Exported Receivers', 'yes')
        audit.setProofsForName('Exported Receivers', proofs)

    if expComps['service']:
        proofs = {}
        for serviceName in expComps['service']:
            tag = soup.find('service', {"android:name": serviceName})
            proofs[tag.prettify()] = list(grep(manifestpath, serviceName).values())[0]

        audit.setFoundForName('Exported Services', 'yes')
        audit.setProofsForName('Exported Services', proofs)

    if expComps['provider']:
        proofs = {}
        for providerName in expComps['provider']:
            tag = soup.find('provider', {"android:name": providerName})
            proofs[tag.prettify()] = list(grep(manifestpath, providerName).values())[0]

        audit.setFoundForName('Exported Providers', 'yes')
        audit.setProofsForName('Exported Providers', proofs)
    mp.close()

def auditInfoPlist(audit):
    payloadPath = audit.folderpath + 'Payload/'
    infoPlistPath = payloadPath + next(os.walk(payloadPath))[1][0] + '/Info.plist'
    with open(infoPlistPath, 'rb') as fp:
        pl = plistlib.load(fp)

        if 'CFBundleIdentifier' in pl:
            audit.setPackageId(pl['CFBundleIdentifier'])

        if 'CFBundleShortVersionString' in pl:
            audit.setPackageVersion(pl['CFBundleShortVersionString'])

        if 'CFBundleVersion' in pl:
            audit.setPackageCodeVersion(pl['CFBundleVersion'])

        if NSAPPTRANSPORTSECURITY in pl:
            if NSALLOWSARBITRARYLOADS in pl[NSAPPTRANSPORTSECURITY]:
                if pl[NSAPPTRANSPORTSECURITY][NSALLOWSARBITRARYLOADS] is True:
                    entry = grepBinary(infoPlistPath, NSALLOWSARBITRARYLOADSBIN)
                    audit.setFoundForName('NS Allows Arbitrary Loads', 'yes')
                    audit.setProofsForName('NS Allows Arbitrary Loads', {json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4): list(entry.values())[0]}) #json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + infoPlistPath)

            if NSALLOWSARBITRARYLOADSFORMEDIA in pl[NSAPPTRANSPORTSECURITY]:
                if pl[NSAPPTRANSPORTSECURITY][NSALLOWSARBITRARYLOADSFORMEDIA] is True:
                    entry = grepBinary(infoPlistPath, NSALLOWSARBITRARYLOADSFORMEDIABIN)
                    audit.setFoundForName('NS Allows Arbitrary Loads For Media', 'yes')
                    audit.setProofsForName('NS Allows Arbitrary Loads For Media', {json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4): list(entry.values())[0]}) #json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + infoPlistPath)

            if NSALLOWSARBITRARYLOADSINWEBCONTENT in pl[NSAPPTRANSPORTSECURITY]:
                if pl[NSAPPTRANSPORTSECURITY][NSALLOWSARBITRARYLOADSINWEBCONTENT] is True:
                    entry = grepBinary(infoPlistPath, NSALLOWSARBITRARYLOADSINWEBCONTENTBIN)
                    audit.setFoundForName('NS Allows Arbitrary Loads In Web Content', 'yes')
                    audit.setProofsForName('NS Allows Arbitrary Loads In Web Content', {json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4): list(entry.values())[0]}) #json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + infoPlistPath)

            if NSALLOWSLOCALNETWORKING in pl[NSAPPTRANSPORTSECURITY]:
                if pl[NSAPPTRANSPORTSECURITY][NSALLOWSLOCALNETWORKING] is True:
                    entry = grepBinary(infoPlistPath, NSALLOWSLOCALNETWORKINGBIN)
                    audit.setFoundForName('NS Allows Local Networking', 'yes')
                    audit.setProofsForName('NS Allows Local Networking', {json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4): list(entry.values())[0]}) #json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + infoPlistPath)

            if NSEXCEPTIONDOMAINS in pl[NSAPPTRANSPORTSECURITY]:
                entry = grepBinary(infoPlistPath, NSEXCEPTIONDOMAINSBIN)
                audit.setFoundForName('NS Exception Domains', 'yes')
                audit.setProofsForName('NS Exception Domains', {json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4): list(entry.values())[0]}) #json.dumps(pl[NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + infoPlistPath)

        fp.close()

def auditResAndroid(audit):
    folderpath = audit.folderpath
    stringsPath = folderpath + 'res/values/strings.xml'
    with open(stringsPath) as f:
        for line in f:
            firebaseDatabaseUrl = re.findall(FIREBASEDATABASEURL, line)
            if firebaseDatabaseUrl:
                audit.setFirebaseDatabaseUrl(firebaseDatabaseUrl[0])

def auditResIos(audit):
    payloadPath = audit.folderpath + 'Payload/'
    googleServiceInfoPlistPath = payloadPath + next(os.walk(payloadPath))[1][0] + '/GoogleService-Info.plist'
    try:
        with open(googleServiceInfoPlistPath, 'rb') as fp:
            pl = plistlib.load(fp)
            if 'DATABASE_URL' in pl:
                audit.setFirebaseDatabaseUrl(pl['DATABASE_URL'])
    except Exception:
        pass

def analyzeUrls(audit, urls):
    basicAuthUrls = {}
    httpInsecureUrls = {}
    qaUrls = {}
    wsInsecureUrls = {}

    if audit.domains:
        for url in list(urls):
            if not any(domain in url for domain in audit.domains):
                del urls[url]

    for url in urls:
        try:
            parsedUrl = urlparse(url)

            if parsedUrl.scheme == 'http':
                httpInsecureUrls[url] = urls[url]

            if parsedUrl.scheme == 'ws':
                wsInsecureUrls[url] = urls[url]
        except Exception:
            pass

        if re.findall(BASICAUTH, url):
            basicAuthUrls[url] = urls[url]

        if any(qatag in url for qatag in QATAGS):
            qaUrls[url] = urls[url]

    if basicAuthUrls:
        audit.setFoundForName('Basic Auth URLs', 'yes')
        audit.setProofsForName('Basic Auth URLs', basicAuthUrls)

    if httpInsecureUrls:
        audit.setFoundForName('Http Insecure URLs', 'yes')
        audit.setProofsForName('Http Insecure URLs', httpInsecureUrls)

    if wsInsecureUrls:
        audit.setFoundForName('WS Insecure URLs', 'yes')
        audit.setProofsForName('WS Insecure URLs', wsInsecureUrls)

    if qaUrls:
        audit.setFoundForName('QA URLs', 'yes')
        audit.setProofsForName('QA URLs', qaUrls)

def search(audit):
    folderpath = audit.folderpath
    files = findfiles(folderpath)
    filesSize = len(files)

    if audit.os is ANDROID:
        blacklistUrls = ANDROIDBLACKLISTURLS
    else:
        blacklistUrls = IOSBLACKLISTURLS

    urls = {}

    for check in audit.checks:
        if check.pattern:
            check.proofs = {}

    for file in files:
        grepAllBinary(file, urls, audit, blacklistUrls)

    if urls:
        analyzeUrls(audit, urls)

    for check in audit.checks:
        if check.pattern:
            if check.proofs:
                check.setFound('yes')
            else:
                check.setProofs('-')

    if audit.os == ANDROID and audit.packages:
        for check in audit.checks:
            if check.pattern and check.tag == 'webview':
                if check.proofs:
                    key = next(iter(check.proofs))
                    filterProofs = []
                    proofsDictValues = check.proofs[key]
                    for proof in proofsDictValues:
                        if any(package in proof for package in audit.packages):
                            filterProofs.append(proof)

                    if filterProofs:
                        check.setFound('yes')
                        check.proofs[key] = filterProofs
                        check.setProofs(check.proofs)
                    else:
                        check.setFound('no')
                        check.setProofs('-')

def findfiles(path):
    res = []
    for root, dirs, fnames in os.walk(path):
        for fname in fnames:
            if os.path.splitext(fname)[1] not in EXTSLIST:
                res.append(os.path.join(root, fname))
    return res

def grepAllBinary(filepath, urls, audit, blacklistUrls):
    i = 0
    with open(filepath, 'rb') as f:
        try:
            for line in f:
                i += 1

                lineUrls = re.findall(URLS, line)
                if lineUrls:
                    for lineUrl in lineUrls:
                        if not any(blacklistUrl in lineUrl for blacklistUrl in blacklistUrls):
                            addFoundToDictBinary(lineUrl, urls, filepath, i)

                for check in audit.checks:
                    if check.pattern:
                        founds = re.findall(check.pattern, line)
                        if founds:
                            for found in founds:
                                addFoundToDictBinary(found, check.proofs, filepath, i)

        except Exception as e:
            pass

        f.close()

def addFoundToDictBinary(found, dict, filepath, line):
    decodedFound = found.decode()
    if decodedFound in dict:
        dict[decodedFound].append(filepath + ':' + str(line))
    else:
        dict[decodedFound] = [filepath + ':' + str(line)]

def grepBinary(filepath, regex):
    res = {}
    i = 0
    with open(filepath, 'rb') as f:
        try:
            for line in f:
                i += 1
                founds = re.findall(regex, line)
                if founds:
                    for found in founds:
                        addFoundToDictBinary(found, res, filepath, i)
        except Exception as e:
            pass
        f.close()
    return res

def addFoundToDict(found, dict, filepath, line):
    if found in dict:
        dict[found].append(filepath + ':' + str(line))
    else:
        dict[found] = [filepath + ':' + str(line)]

def grep(filepath, regex):
    res = {}
    i = 0
    with open(filepath) as f:
        try:
            for line in f:
                i += 1
                founds = re.findall(regex, line)
                if founds:
                    for found in founds:
                        addFoundToDict(found, res, filepath, i)
        except Exception as e:
            pass
    f.close()
    return res

def isNullOrEmptyString(input_string, strip_whitespaces=False):
    if input_string is None :
        return True
    if strip_whitespaces :
        if input_string.strip() == "" :
            return True
    else :
        if input_string == "" :
            return True
    return False

def getExportedComponents(manifestPath):
    res = {"activity": [], 'activity-alias': [], 'receiver': [], 'service': [], 'provider': []}

    PROTECTION_NORMAL = 0
    PROTECTION_DANGEROUS = 1
    PROTECTION_SIGNATURE = 2

    xml = minidom.parse(manifestPath)
    xml.normalize()

    PermissionName_to_ProtectionLevel = {}
    for item in xml.getElementsByTagName("permission"):
        name = item.getAttributeNS(NSANDROIDURI, "name")
        protectionLevel = item.getAttributeNS(NSANDROIDURI, "protectionLevel")
        if name is not None:
            try:
                if protectionLevel == "" :
                    PermissionName_to_ProtectionLevel[name] = 0
                else :
                    PermissionName_to_ProtectionLevel[name] = int(protectionLevel, 16)  #translate hex number to int
            except ValueError:
                PermissionName_to_ProtectionLevel[name] = 0

    list_ready_to_check = []
    find_tags = ["activity", "activity-alias", "service", "receiver"]

    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            name = item.getAttribute("android:name")
            exported = item.getAttribute("android:exported")
            permission = item.getAttribute("android:permission")
            has_any_actions_in_intent_filter = False
            if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):

                is_ready_to_check = False
                is_launcher = False
                has_any_non_google_actions = False
                isSyncAdapterService = False
                for sitem in item.getElementsByTagName("intent-filter"):
                    for ssitem in sitem.getElementsByTagName("action"):
                        has_any_actions_in_intent_filter = True

                        action_name = ssitem.getAttribute("android:name")
                        if (not action_name.startswith("android.")) and (not action_name.startswith("com.android.")):
                            has_any_non_google_actions = True

                        if (action_name == "android.content.SyncAdapter"):
                            isSyncAdapterService = True

                    for ssitem in sitem.getElementsByTagName("category"):
                        category_name = ssitem.getAttribute("android:name")
                        if category_name == "android.intent.category.LAUNCHER":
                            is_launcher = True

                # exported="true" or exported not set
                if exported == "":
                    if has_any_actions_in_intent_filter:
                        # CHECK
                        is_ready_to_check = True

                elif exported.lower() == "true":  # exported = "true"
                    # CHECK
                    is_ready_to_check = True

                if (is_ready_to_check) and (not is_launcher):
                    list_ready_to_check.append((tag, name, exported, permission, has_any_non_google_actions,
                                                has_any_actions_in_intent_filter, isSyncAdapterService))
    # ------------------------------------------------------------------------
    # CHECK procedure
    list_implicit_service_components = []

    list_alerting_exposing_components_NonGoogle = []
    list_alerting_exposing_components_Google = []
    for i in list_ready_to_check:
        component = i[0]
        permission = i[3]
        hasAnyNonGoogleActions = i[4]
        has_any_actions_in_intent_filter = i[5]
        isSyncAdapterService = i[6]
        is_dangerous = False
        if permission == "":  # permission is not set
            is_dangerous = True
        else:  # permission is set
            if permission in PermissionName_to_ProtectionLevel:
                protectionLevel = PermissionName_to_ProtectionLevel[permission]
                if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
                    is_dangerous = True
            # else: #cannot find the mapping permission
            #   is_dangerous = True

        if is_dangerous:
            if (component == "service") and (has_any_actions_in_intent_filter) and (not isSyncAdapterService):
                list_implicit_service_components.append(i[1])

            if hasAnyNonGoogleActions:
                if i not in list_alerting_exposing_components_NonGoogle:
                    list_alerting_exposing_components_NonGoogle.append(i)
            else:
                if i not in list_alerting_exposing_components_Google:
                    list_alerting_exposing_components_Google.append(i)

    if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google:
        if list_alerting_exposing_components_NonGoogle:
            for i in list_alerting_exposing_components_NonGoogle:
                res[i[0]].append(i[1])

        if list_alerting_exposing_components_Google:
            for i in list_alerting_exposing_components_Google:
                res[i[0]].append(i[1])

    # ------------------------------------------------------------------------
    # "exported" checking (provider):
    # android:readPermission, android:writePermission, android:permission
    list_ready_to_check = []

    for item in xml.getElementsByTagName("provider"):
        name = item.getAttribute("android:name")
        exported = item.getAttribute("android:exported")

        if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):
            # exported is only "true" or non-set
            permission = item.getAttribute("android:permission")
            readPermission = item.getAttribute("android:readPermission")
            writePermission = item.getAttribute("android:writePermission")
            has_exported = True if (exported != "") else False

            list_ready_to_check.append((name, exported, permission, readPermission, writePermission, has_exported))

    list_alerting_exposing_providers_no_exported_setting = []  # providers that Did not set exported
    list_alerting_exposing_providers = []  # provider with "true" exported
    for i in list_ready_to_check:  # only exist "exported" provider or not set
        exported = i[1]
        permission = i[2]
        readPermission = i[3]
        writePermission = i[4]
        has_exported = i[5]

        is_dangerous = False
        list_perm = []
        if permission != "":
            list_perm.append(permission)
        if readPermission != "":
            list_perm.append(readPermission)
        if writePermission != "":
            list_perm.append(writePermission)

        if list_perm:  # among "permission" or "readPermission" or "writePermission", any of the permission is set
            for self_defined_permission in list_perm:  # (1)match any (2)ignore permission that is not found
                if self_defined_permission in PermissionName_to_ProtectionLevel:
                    protectionLevel = PermissionName_to_ProtectionLevel[self_defined_permission]
                    if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
                        is_dangerous = True
                        break

        else:  # none of any permission
            if exported.lower() == "true":
                is_dangerous = True

        if is_dangerous:
            list_alerting_exposing_providers.append(i)  # exported="true" and none of the permission are set => of course dangerous

    if list_alerting_exposing_providers:
        for i in list_alerting_exposing_providers:
            res['provider'].append(i[0])

    return res

def sortChecks(checks, result):
    for check in checks:
        if check.tag in result:
            result[check.tag].append(check)
        else:
            result[check.tag] = [check]

def getHtmlReport(audit):
    for check in audit.checks:
        if check.found == 'yes':
            if audit.os == 'android':
                if check.tag == 'network':
                    check.proofs = json.dumps(check.proofs[0], sort_keys = True, indent = 4) + '\n' + escape(list(check.proofs[1].keys())[0]) + ":\n" + list(check.proofs[1].values())[0][0]
                elif check.tag == 'components':
                    proofs = ''
                    for key, value in check.proofs.items():
                        proofs += escape(key) + ':' + value[0] + '\n\n'
                    check.proofs = proofs
                else:
                    check.proofs = json.dumps(check.proofs, sort_keys = True, indent = 4)
            if audit.os == 'ios':
                if check.tag == 'network':
                    check.proofs = list(check.proofs.keys())[0] + ':\n' + list(check.proofs.values())[0][0]
                else:
                    check.proofs = json.dumps(check.proofs, sort_keys=True, indent=4)

    result = {'os': audit.os, 'filename': audit.filename, 'packageId': audit.packageId, 'packageVersion': audit.packageVersion,
               'packageCodeVersion': audit.packageCodeVersion, 'firebaseDatabaseUrl': audit.firebaseDatabaseUrl,
              'startTime': audit.startTime, 'time': audit.time, 'checks': {}, 'summary': audit.summary}

    sortChecks(audit.checks, result['checks'])

    if audit.os is ANDROID:
        templateFile = "androidtemplate.html"
    else:
        templateFile = "iostemplate.html"

    templateLoader = FileSystemLoader(searchpath="./")
    templateEnv = Environment(loader=templateLoader)
    template = templateEnv.get_template(templateFile)

    return template.render(result=result)

def getSarifReport(audit):
    log = om.SarifLog(
        schema_uri="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
        version="2.1.0",
        runs=[
            om.Run(
                tool=om.Tool(driver=om.ToolComponent(name="CheckKarlMarx")),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                    )
                ]
            )
        ],
    )

    run = log.runs[0]
    add_results(audit, run)

    serializedLog = to_json(log)
    return serializedLog

def add_results(audit, run):
    if run.results is None:
        run.results = []

    rules = {}
    rule_indices = {}
    for check in audit.checks:
        if check.found == 'yes':
            if check.tag == 'network':
                if audit.os == ANDROID:
                    result = create_result(check.id, check.name, check.severity, check.info, list(check.proofs[1].keys())[0], list(check.proofs[1].values())[0][0], rules, rule_indices)
                else:
                    result = create_result(check.id, check.name, check.severity, check.info, list(check.proofs.keys())[0], list(check.proofs.values())[0][0], rules, rule_indices)
                run.results.append(result)
            else:
                for key, value in check.proofs.items():
                    for location in value:
                        result = create_result(check.id, check.name, check.severity, check.info, key, location, rules, rule_indices)
                        run.results.append(result)

    if len(rules) > 0:
        run.tool.driver.rules = list(
            rules.values()
        )

def create_result(checkId, checkName, checkSeverity, checkInfo, key, location, rules, rule_indices):
    rule, rule_index = create_or_find_rule(checkId, checkName, rules, rule_indices)

    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=to_uri(location.split(':')[0]))
    )

    physical_location.region = om.Region(
        start_line=int(location.split(':')[1]), snippet=om.ArtifactContent(text=key)
    )

    return om.Result(
        rule_id=checkId,
        rule_index=rule_index,
        message=om.Message(text=checkInfo),
        level=level_from_severity(checkSeverity),
        locations=[om.Location(physical_location=physical_location)],
    )

def create_or_find_rule(checkId, checkName, rules, rule_indices):
    rule_id = checkId
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]

    rule = om.ReportingDescriptor(
        id=rule_id, name=checkName
    )

    index = len(rules)
    rules[rule_id] = rule
    rule_indices[rule_id] = index
    return rule, index

def to_uri(file_path):
    pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        posix_path = pure_path.as_posix()
        return quote(posix_path)

def level_from_severity(severity):
    if severity == "Major" or severity == "Normal":
        return "error"
    elif severity == "Minor":
        return "warning"
    elif severity == "Info":
        return "note"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--format", nargs='?', default="html", const="html", choices=['html', 'sarif'], help="report format: html or sarif")
    parser.add_argument("-o", "--out", nargs='?', default="file", const="file", choices=['file', 'stdout'], help="print output to: file or stdout")
    parser.add_argument("-d", "--domains", nargs='*', help="domain list (e.g. example.com)")
    parser.add_argument("-q", "--qatags", nargs='*', help="test domain tags list")
    parser.add_argument("-p", "--packages", nargs='*', help='package names (android only, e.g. com.example)')
    args = parser.parse_args()

    if args.qatags:
        global QATAGS
        QATAGS = args.qatags

    if args.packages:
        for i in range(len(args.packages)):
            args.packages[i] = args.packages[i].replace(".", "/")

    filepath = ''

    for file in os.listdir(MOUNTDIR):
        if getExtension(file) in ALLOWED_EXTS:
            filepath = file
            break

    if filepath:
        filepath = MOUNTDIR + filepath
        extension = getExtension(filepath)
        filename = getCleanName(filepath)
        folderpath = getNameWithoutExt(filename) + '/'
        checks = []
        nameToIndexMap = {}
        startTime = datetime.now()
        summary = {'Major': 0, 'Normal': 0, 'Minor': 0, 'Info': 0}

        if extension == APK:
            platform = ANDROID
        else:
            platform = IOS

        index = 0
        for check in CHECKS:
            if check['os'] == platform or check['os'] == ALL:
                nameToIndexMap[check['name']] = index
                check = Check(id=check['id'], name=check['name'], tag=check['tag'], severity=check['severity'], pattern=check.get('pattern'), found='no', proofs='-', info=check['info'])
                checks.append(check)
                index += 1

        audit = Audit(startTime=startTime, os=platform, filename=filename, filepath=filepath, folderpath=folderpath, checks=checks, domains=args.domains, packages=args.packages, firebaseDatabaseUrl='-', summary=summary, nameToIndexMap=nameToIndexMap)
        try:
            if platform is ANDROID:
                androidAudit(audit)
            else:
                iosAudit(audit)

            for check in audit.checks:
                if check.found == "yes":
                    audit.summary[check.severity] += 1

            if args.format == 'html':
                report = getHtmlReport(audit)
            elif args.format == 'sarif':
                report = getSarifReport(audit)

            if args.out == 'file':
                reportfile = "report." + args.format
                with open(MOUNTDIR + reportfile, 'w') as f:
                    f.write(report)
            elif args.out == 'stdout':
                print(report)

            if summary['Normal'] or summary['Major']:
                exit(1)
            else:
                exit(0)

        except Exception as e:
            print(e)
            exit(2)
    else:
        print("There is no apk or ipa file in /mount folder")
        exit(2)

if __name__ == "__main__":
    main()