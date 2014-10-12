#!/usr/bin/env python
# @Author: lnxg33k
# @Date:   2014-10-08 03:47:26
# @Last Modified by:   lnxg33k
# @Last Modified time: 2014-10-12 20:35:28

"""
In order to interact with the Safe Browsing lookup server,
you need an API key to authenticate as an API user.
You will pass this key as a CGI parameter

1. Create a project in the Google Developers Console.
2. In your project, click on APIs & Auth > APIs.
3. Scroll down to the Safe Browsing API and turn it ON.
4. Click on APIs & Auth > Credentials.
5. Click on Create new key and create a browser or server key.
"""

from urllib2 import Request, urlopen
from sys import argv
from json import dumps

key = "--- INSERT YOUR KEY HERE ----"

url = "https://sb-ssl.google.com/safebrowsing/api"
url += "/lookup?client=lnxg33k_client&key=%s&appver=1.5.2&pver=3.1" % key


def chunks(l, n=500):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def lookUp(domains=[]):
    result = {}
    chunked_domains = chunks(domains)
    for chunk in chunked_domains:
        data = "%s\n%s" % (len(chunk), "\n".join(chunk))
        try:
            req = Request(url, data)
            r = urlopen(req)
            if r.code == 200:
                result.update(dict(zip(
                    chunk,
                    map(lambda n: {'google': n}, map(str.strip, r.readlines())))
                ))
        except:
            pass
    return result


def main():
    if len(argv) != 3:
        exit("[+] Usage: %s <input> <output>" % argv[0])

    list_of_domains = argv[1]
    output = argv[2]

    print "[-] Loading domains from %s ..." % list_of_domains
    with open(list_of_domains, 'r') as f:
        domains = map(str.strip, f.readlines())
        domains = list(set(domains))
    print "[-] Got %s unique domains from the list" % len(domains)

    print (
        "\n[-] Sending domains to Google lookup API" +
        " (will take some time depending on the size of the lisy)..."
    )
    result = lookUp(domains)

    print "\n[-] Dumping data to %s ..." % output
    with open(output, 'w') as output_file:
        output_file.write(dumps(result, indent=2))
    print "[-] Successfully dumped data !!"

if __name__ == '__main__':
    main()
