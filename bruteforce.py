#!/usr/bin/env python

# from sys import argv
from requests import request, packages
from multiprocessing.dummy import Pool as ThreadPool
from progressbar import ProgressBar, SimpleProgress

packages.urllib3.disable_warnings()


def getFullUrls(url, paths, ext=[]):
    urls = []
    for path in paths:
        if path:
            urls.append("%s/%s" % (url.rstrip('/'), path.strip('/')))
            if ext:
                for i in ext:
                    fullUrl = "%s/%s.%s" % (
                        url.rstrip('/'), path.strip('/'), i.strip('.'))
                    urls.append(fullUrl)
    return urls


def fileExists(url, foundCodes=[], cookies=None):
    if cookies:
        cookiesDict = {}
        for i in cookies.split(';'):
            i = map(str.strip, i.split('='))
            cookiesDict[i[0]] = i[1]
    else:
        cookiesDict = None

    try:
        r = request("GET", url, cookies=cookiesDict, timeout=5, verify=False)
        responseHeaders = dict(r.headers.lower_items())
        if r.status_code in foundCodes:
            data = {
                'url': url.strip('/'), 'code': r.status_code,
                'Content-Type': responseHeaders.get('content-type'),
                'Content-Length': responseHeaders.get('content-length') or 0
            }
            print "[+] %s (code:%d|Content-Type:%s|Content-Length:%s)" % (
                url, data['code'], data['Content-Type'],
                data['Content-Length'])
            return data
    except Exception, e:
        print e.message

with open('/Users/lnxg33k/pentest/web/dirb/wordlists/common.txt') as f:
    paths = filter(None, map(str.strip, f.readlines()))

urls = getFullUrls("http://google.com/", paths, ext=['.php'])


result = []
pool = ThreadPool(60)
pbar = ProgressBar(widgets=[SimpleProgress()], maxval=len(urls)).start()
r = [pool.apply_async(
        fileExists, (x, [307, 200, 204, 301, 302], ), callback=result.append
        ) for x in urls]
while len(result) != len(urls):
    pbar.update(len(result))
pbar.finish()
# pool.map(fileExists, (x, [200], cookies), )
# %time poolResults = pool.map(vTotal, urls)
pool.close()
pool.join()
