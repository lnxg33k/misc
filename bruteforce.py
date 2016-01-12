#!/usr/bin/env python
# Dirb alternative in python
# By Ahmed Shawky @lnxg33k

import sys
import uuid
from requests import request, packages
from multiprocessing.dummy import Pool as ThreadPool
from progressbar import ProgressBar, SimpleProgress
import time
import logging

logging.basicConfig(level=logging.INFO, format='[+] %(asctime)s - %(message)s')
logger = logging.getLogger('BruteForce')
logging.getLogger("requests").setLevel(logging.WARNING)
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


def notFoundCode(url, cookies=None, userAgent=None):
    url = '%s/%s' % (url.strip('/'), uuid.uuid4())
    r = request(
        "HEAD", url, cookies=cookieFormatter(cookies),
        timeout=10, verify=False)
    return r.status_code


def cookieFormatter(cookies):
    if cookies:
        cookiesDict = {}
        for i in cookies.split(';'):
            i = map(str.strip, i.split('='))
            cookiesDict[i[0]] = i[1]
        return cookiesDict
    else:
        return None


def fileExists(url, notFound=404, ignoreCodes=[], cookies=None, sleep=4):
    try:
        r = request(
            "HEAD", url, cookies=cookieFormatter(cookies),
            headers={'User-Agent': 'Mozilla'}, verify=False, timeout=2)
        responseHeaders = dict(r.headers.lower_items())
        if r.status_code != notFound and r.status_code not in ignoreCodes:
            data = {
                'url': url.strip('/'), 'code': r.status_code,
                'Content-Type': responseHeaders.get('content-type'),
                'Content-Length': responseHeaders.get('content-length') or 0
            }
            logger.info(" %s (code:%d|Content-Type:%s|Content-Length:%s)" % (
                url, data['code'], data['Content-Type'],
                data['Content-Length']))
            return data
    except Exception, e:
        # print e.message
        pass
    finally:
        time.sleep(sleep)


if __name__ == '__main__':

    if len(sys.argv) != 5:
        msg = "Usage) %s <url> <Wordlist> <extensions> <threads>" % sys.argv[0]
        msg += "\nExample: %s http://lnxg33k.me file.txt .php 30" % sys.argv[0]
        exit(msg)

    url = sys.argv[1]
    with open(sys.argv[2]) as f:
        paths = list(set(filter(None, map(str.strip, f.readlines()))))
    extensions = sys.argv[3].split(',')
    threads = int(sys.argv[4])
    urls = getFullUrls(url, paths, ext=extensions)

    print "\n==================================================="
    print "[!] PyBirb [Dirb in Python with more features]."
    print "[!] By: Ahmed Shawky @lnxg33k."
    print "-------------"
    notFound = notFoundCode(url=url)
    print "[-] NotFound Code : %d" % notFound
    print "[-] Wordlist      : %s" % sys.argv[2]
    print "[-] Threads       : %d" % threads
    print "[-] Extensions    : %s" % ', '.join(extensions)
    print "====================================================\n"

    result = []
    pool = ThreadPool(threads)
    pbar = ProgressBar(widgets=[SimpleProgress()], maxval=len(urls)).start()
    r = [pool.apply_async(
            fileExists, (x, notFound, [300], None, 4), callback=result.append
            ) for x in urls]
    while len(result) != len(urls):
        pbar.update(len(result))
    pbar.finish()
    pool.close()
    pool.join()
