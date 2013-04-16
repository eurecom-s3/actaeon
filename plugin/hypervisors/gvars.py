# Volatility
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




#--------------------------------------
# Global Variables
#--------------------------------------


# PAE global variable
pae = 0 
# Nested Virtualization Global variable
nested = 0 
# List containing the VMCS found in the memory dump. The value is the physical address.
vmcs_found = []
# List for nested VMCS found
nvmcs_found = []
# Dictionary for generic VMCS CR3
generic_vmcs_cr3 = {}
# List for generic VMCS
generic_vmcs = []
# Global flag to know if the I/O Bitmaps are used or not.
iobitmaps = 0 
# Physical Address of IO Bitmap A
iobitmapa = 0 
# Physical Address of IO Bitmap B
iobitmapb = 0 
# Table 20-6 - Bit Positions 31: Acitivate Secondary Controls
use_secondary_control = 0 
# Table 20-6 - Bit Positions 28: Use MSR Bitmaps
use_msr_bitmaps = 0 
# Dictionary of the hypervisor pages
hypervisor_pages = {}

# Command line options:
f = d = vrb = nest = sign = weird = generic = False
pages = dump = arch = algo = None


