#!/usr/bin/env python

import time
import struct
import sys

attributestrings = ["Read only",
                    "Hidden",
                    "System file",
                    "Volume label",
                    "Directory",
                    "Modified since last backup", #?
                    "Encrypted",
                    "Normal", #!? 
                    "Temporary",
                    "Sparse file",
                    "Reparse point data", #!?!?
                    "Compressed",
                    "Offline"]

flagstrings = [ "Shell item ID list", 
                "Points to a file",
                "Description string",
                "Has relative path", 
                "Has working directory", 
                "Has command line arguments",
                "Has a custom icon"]

def windowsTimeToUnix(wintime):
    #Taken from
    #http://code.activestate.com/recipes/303344/
    h = ((wintime >> 32) & 0xFFFFFFFF)
    l = (wintime & 0x00000000FFFFFFFF)
    d=116444736000000000L #difference between 1601 and 1970
    return (((long(h)<< 32) + long(l))-d)/10000000

def intToFlags(flagnum, number):
    results = []

    for i in xrange(number):
        results.append(flagnum & 0x1)
        flagnum = flagnum >> 1
    return results

def parseLnk(thefile):
    data = thefile.read(4)
    headernum = struct.unpack("i", data)
    
    print "Header: 0x%x" % headernum
    
    data = thefile.read(16)
    guid = struct.unpack("iiii", data)

    print "GUID: 0x%08x-%08x-%08x-%08x" % guid
    
    data = thefile.read(4)
    flags = struct.unpack("i", data)[0]

    print "Flags: 0x%x" % flags
    
    flagresults = intToFlags(flags, 7)

    for i, flagname in enumerate(flagstrings):
        print " %s: %d" % (flagname, flagresults[i])

    data = thefile.read(4)
    attributes = struct.unpack("i", data)[0]

    print "Attributes: 0x%x" % attributes
    attrresults = intToFlags(attributes, 13)

    for i, attname in enumerate(attributestrings):
        print " %s: %d" % (attname, attrresults[i])

    data = thefile.read(8)
    time1 = struct.unpack("q", data)[0]
    print "Creation time: " + time.ctime(windowsTimeToUnix(time1))
    
    data = thefile.read(8)
    time2 = struct.unpack("q", data)[0]
    print "Modification time: " + time.ctime(windowsTimeToUnix(time2))

    data = thefile.read(8)
    time3 = struct.unpack("q", data)[0]
    print "Last access time: " + time.ctime(windowsTimeToUnix(time3))

    data = thefile.read(4)
    length = struct.unpack("i", data)
    print "Length (only set if there is a custom icon in use): %x" % length

    data = thefile.read(4)
    iconno = struct.unpack("i", data)
    print "Icon number: %x" % iconno

    data = thefile.read(4)
    showwnd = struct.unpack("i", data)
    print "ShowWnd: %x" % showwnd

    data = thefile.read(4)
    hotkey = struct.unpack("i", data)
    print "Hotkey: %x" % hotkey

    data = thefile.read(4)
    junk = struct.unpack("i", data)
    print "Junk1: %x" % junk

    data = thefile.read(4)
    junk = struct.unpack("i", data)
    print "Junk2: %x" % junk

def main():
    if (len(sys.argv) <= 1):
        print "Provide a file please"
        sys.exit(1)

    thefile = open(sys.argv[1], "r")
    parseLnk(thefile)

if __name__ == "__main__":
    main()
