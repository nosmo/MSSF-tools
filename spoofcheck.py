#!/usr/bin/env python

import subprocess

"""Quick hack to check for ARP-spoofing hosts.

 Written with Mac OS X's /usr/sbin/arp in mind.

"""

__author__ = "nosmo@netsoc.tcd.ie"

def ParseList():
    
    listproc = subprocess.Popen("/usr/sbin/arp -a", shell=True, stdout=subprocess.PIPE)
    output = listproc.communicate()[0].split("\n")
    splitlines = [i.split(" ") for i in output if i]

    macs = {}
    #blank line
    del(splitlines[:0])

    for i in splitlines:
        if i[3] in macs:
            macs[i[3]].append(i[1])
        else:
            macs[i[3]] = [i[1]]

    return macs

def CheckList(maclist):
    foundhosts = False
    for m in maclist.keys():
        if len(maclist[m]) > 1 and m != "ff:ff:ff:ff:ff:ff":
            foundhosts = True
            print "%s may be ARP spoofing!" % m
            print " The following hosts are associated with the MAC address: "
            for h in maclist[m]:
                print h

    return foundhosts

def main():

    m = ParseList()
    if not CheckList(m):
        print "Everything LOOKS okay. Yay!"

if __name__ == "__main__":
    main()
