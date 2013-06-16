#
# Mariano `emdel` Graziano - graziano@eurecom.fr
# Simple VMCS data structure extractor from dmesg 
# output.
#

import sys


if len(sys.argv) != 2:
    print "Usage: %s %s" % (sys.argv[1], "dmesg")
    sys.exit(-1)


h = {}
fd = open(sys.argv[1], "r")
for d in fd.readlines():
    if "entry #" in d:
        name = d.strip().split()[3]
        value = d.strip().split()[6]
        if name not in h:
            h[name] = value
fd.close()


i = 0
tot = len(h.keys())
print "vmcs = {"
for k, v in h.items():
   i += 1
   if i != tot:
       print "\"%s\": 0x%s," % (k, v)
   else:
       print "\"%s\": 0x%s" % (k, v)
print "}"
