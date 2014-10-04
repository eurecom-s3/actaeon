#
# Mariano `emdel` Graziano - graziano@eurecom.fr
# Convert the Rekall VMCS layout format to the Actaeon one.
#


import sys, json, requests, gzip, os


REKALL_VMCS_REPOSITORY = "https://github.com/google/rekall-profiles/blob/gh-pages/v1.0/VMCS.gz?raw=true"
NAME = "VMCS.gz"
ACTAEON_MICROARCH = ["PENRYN_VMCS", "SANDYBRIDGE_VMCS", "WESTMERE_VMCS", "KVM_NESTED_VMCS", "VMWARE_NESTED_VMCS"]
LICENSE = """
 #
 # VMCS Memory layout converted from Google Rekall Repository with
 # rekall2actaeon.py 
 #
 # Authors: 
 # Mariano `emdel` Graziano - graziano@eurecom.fr
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; either version 2 of the License, or (at
 # your option) any later version.
 #
 # This program is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 #
"""


def parse_google_json(structures):
    for s1, v1 in structures["$STRUCTS"].items():
        if s1 not in ACTAEON_MICROARCH:
            print "[+] Converting %s:" % s1
            filename = "%s%s" % (s1.lower().split('_')[0], ".py")
            h = open(filename, 'w')
            print "\t - %s created" % filename
            h.write(LICENSE)
            h.write("\n\n\n")
            h.write("vmcs = {\n")
            tot = len(v1[1].keys())
            i = 0
            for field_name, fv in v1[1].items():
                i += 1
                if i != tot:
                    field_content = "\"%s\": %s,\n" % (field_name, hex(fv[0]/4))
                    h.write(field_content)
                else: 
                    field_content = "\"%s\": %s\n" % (field_name, hex(fv[0]/4))
                    h.write(field_content)
            h.write("}\n")
            h.close()


def main():
    if len(sys.argv) != 2:
        print "[-] Usage: %s %s" % (sys.argv[0], "<output dir>")
        sys.exit(-1)

    # Check if NAME already exists
    filename = os.path.join(sys.argv[1], NAME)
    if not os.path.exists(filename):
        # Get the VMCS.gz
        print "[+] Downloading %s from %s" % (NAME, REKALL_VMCS_REPOSITORY)
        r = requests.get(REKALL_VMCS_REPOSITORY)
        fo = open(NAME, 'wb')
        for chunk in r.iter_content():
            fo.write(chunk)
        fo.close()
    
    # Decompression
    print "[+] Decompressing %s" % NAME
    vmcs_fd = gzip.open(NAME, 'rb')
    rekall_vmcs = vmcs_fd.read()
    
    # JSON
    google_vmcs = json.loads(rekall_vmcs)
    
    # Parsing Google JSON VMCS file
    parse_google_json(google_vmcs)

main()
