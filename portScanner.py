#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: lnxg33k
# @Date:   2015-02-08 01:47:45
# @Last Modified by:   lnxg33k
# @Last Modified time: 2015-02-08 01:48:24

from sys import argv
from functools import partial
from multiprocessing import Pool
from socket import socket, setdefaulttimeout, error, gethostbyname

processes = 200
setdefaulttimeout(.5)


def ping(host, port):
    try:
        s = socket()
        s.connect((host, port))
        try:
            return (port, s.recv(1024))
        except:
            return (port, None)  # increase the timeout to get more data
    except error:
        if error.errno == 111:  # connection refused
            pass


def threadedScan(host):
    p = Pool(processes)
    pingHost = partial(ping, host)
    return filter(bool, p.map(pingHost, range(1, 65536)))


def main():
    # host = "127.0.0.1"
    host = gethostbyname(argv[1])
    print "[+] Scanning {} ...".format(host)
    opendPorts = list(threadedScan(host))
    print opendPorts

if __name__ == "__main__":
    main()
