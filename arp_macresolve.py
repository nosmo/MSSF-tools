#!/usr/bin/env python

# "Resolve" MAC addresses from an arp table dump on OS X
# Just a cosmetic dalliance more than anything

import subprocess

def ParseList():
    # get the hosts
    listproc = subprocess.Popen("/usr/sbin/arp -a", shell=True, stdout=subprocess.PIPE)
    output = listproc.communicate()[0].split("\n")
    splitlines = [i.split(" ") for i in output if i]

    macs = {}
    #blank line
    del(splitlines[:0])

    for i in splitlines:
        if i[3].startswith("0:"):
            # arp cuts off the leading zero
            i[3] = "0"+i[3]
            
        macs[i[3].replace(":","")] = i[1]

    return macs

def ParseMacs(path="/Users/nosmo/Portage/usr/share/nmap/nmap-mac-prefixes"):
    # Parse out the mac/manufacturer list
    macs = {}
    data = open(path).readlines()
    d = lambda a,b: macs.update({a:b})
    # I apologise for nothing
    [ d(i.lower(),j) for i,j in [ z.split(" ", 1) for z in data ] ]
    return macs

def main():
    macdb = ParseMacs()
    hosts = ParseList()

    for i in hosts.keys():
        vendor = ""
        if i[:6] in macdb:
            vendor = macdb[i[:6]]
        print "%s: %s, %s" % (hosts[i], i, vendor)

if __name__ == "__main__":
    main()
