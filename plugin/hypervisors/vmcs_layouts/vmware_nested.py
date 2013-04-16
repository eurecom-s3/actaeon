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



'''
VMWare Workstation 9.0.1 VMCS12 important fields.
Tested on Sandy Bridge Microarch, on a 32bit OS
'''
vmcs = {
"VMCS_LINK_POINTER": 0x2e8,
"GUEST_CR3": 0x8b0,
"HOST_CR3": 0xa20,
"HOST_RIP": 0xa70,
"GUEST_RIP": 0x920,
"CR3_TARGET_VALUE0": 0x5e8
}
