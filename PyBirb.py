#!/usr/bin/env python
# Dirb alternative in python
# By Ahmed Shawky @lnxg33k

import sys
import uuid
from requests import request, packages
from multiprocessing.dummy import Pool as ThreadPool
from progressbar import ProgressBar, SimpleProgress
import time
import argparse
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
        headers={'User-Agent': userAgent},
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


def fileExists(url, notFound=404, ignoreCodes=[], cookies=None, sleep=0, agent=None):
    try:
        r = request(
            "HEAD", url, cookies=cookieFormatter(cookies),
            headers={'User-Agent': agent}, verify=False, timeout=2)
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

    if len(sys.argv) <= 1:
        msg = "usage: %s -h" % sys.argv[0]
        exit(msg)

    parser = argparse.ArgumentParser()
    args = parser.add_argument_group('Options')
    args.add_argument('-u', '--url', dest='url', metavar='', help='\t\tThe target URL to scan.')
    args.add_argument('-w', '--wordlist', dest='wordlist', metavar='', help='\t\tPath to the wordlist.')
    args.add_argument('-e', '--extensions', dest='extensions', metavar='', help='\t\tAppend each word with theae extensions (e.g. asp,aspx).')
    args.add_argument('-t', '--threads', dest='threads', type=int, default=30, metavar='', help='\t\tNumber of concurrent threads (default 30).')

    connection = parser.add_argument_group('Connection')
    connection.add_argument('-c', '--cookie', dest='cookie', metavar='', help='\t\tSet a cookie to the request.')
    connection.add_argument('-ua', '--user-agent', dest='agent', metavar='', help='\t\tSpoof the request User-Agent.')
    connection.add_argument('-s', '--sleep', dest='sleep', type=int, default=0, metavar='', help='\t\tTime to sleep between concurrent requests. (default 0)')
    connection.add_argument('-i', '--ignore', dest='ignore', default=[], metavar='', help='\t\t HTTP response status codes to ignore (e.g. 300,500).')
    options = parser.parse_args()

    url = options.url
    if options.ignore:
        options.ignore = map(int, options.ignore.split(','))
    with open(options.wordlist) as f:
        paths = list(set(filter(None, map(str.strip, f.readlines()))))
    extensions = options.extensions.split(',')
    threads = options.threads

    urls = getFullUrls(url, paths, ext=extensions)

    print "\n==================================================="
    print "[!] PyBirb [Dirb in Python with more features]."
    print "[!] By: Ahmed Shawky @lnxg33k."
    print "-------------"
    notFound = notFoundCode(url=url, cookies=options.cookie, userAgent=options.agent)
    print "[-] NotFound Code : %d" % notFound
    print "[-] Ignore Codes  : %s" % options.ignore
    print "[-] Wordlist      : %s" % options.wordlist
    print "[-] Extensions    : %s" % ', '.join(extensions)
    print "[-] Threads       : %d" % threads
    print "[-] Wait          : %d" % options.sleep
    print "====================================================\n"

    result = []
    pool = ThreadPool(threads)
    pbar = ProgressBar(widgets=[SimpleProgress()], maxval=len(urls)).start()
    r = [pool.apply_async(
            fileExists, (x, notFound, options.ignore, options.cookie, options.sleep, options.agent), callback=result.append
            ) for x in urls]
    while len(result) != len(urls):
        pbar.update(len(result))
    pbar.finish()
    pool.close()
    pool.join()
