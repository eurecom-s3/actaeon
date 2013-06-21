#
# Mariano `emdel` Graziano - graziano@eurecom.fr
#

import struct, sys
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.hypervisors.vmcs_layouts as layouts
import volatility.plugins.hypervisors.gvars as hyper
import volatility.scan as scan
import volatility.commands as commands
import volatility.conf as conf


vmcs_offset = None
prev_layout = None
nvalidated = prev_saved = 0
hypervisor_pages = {}
generic_vmcs_cr3 = {}
memory = None
vmcs12 = None
revision_id = None

class RevisionIdCheck(scan.ScannerCheck):
    """
    Revision ID check
    Check whether the first word is in the possible/known values...
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        global revision_id
        data = self.address_space.read(offset, 0x04)
        entry = struct.unpack('<I', data)[0]

        if entry == revision_id:
            return True
        else:
            return False


    def skip(self, data, offset):
        return 4096



class SecondEntryCheck(scan.ScannerCheck):
    """
    VMCS Second Entry check
    Second entry must be zero.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        data = self.address_space.read(offset + 0x04, 0x04)
        second_entry = struct.unpack('<I', data)[0]
        return second_entry == 0x00


    def skip(self, data, offset):
        return 4096



class VmcsLinkPointerCheck(scan.ScannerCheck):
    """
    VMCS Link Pointer check
    64 bit set at 0xffffffff.
    """
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        global vmcs_offset
        off = vmcs_offset["VMCS_LINK_POINTER"] * 4
        data = self.address_space.read(offset + off, 0x04)
        vmcs_link_pointer = struct.unpack('<I', data)[0]
        data2 = self.address_space.read(offset + off + 0x04, 0x04)
        vmcs_link_pointer2 = struct.unpack('<I', data2)[0]
        if (vmcs_link_pointer == 0xffffffff and vmcs_link_pointer2 == 0xffffffff):
            return True
        return False

    def skip(self, data, offset):
        return 4096


class VMXEnableCheck(scan.ScannerCheck):
    """
    VMCS VMX enabled check
    CR4.VMX bit 13.
    """
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        global vmcs_offset
        off = vmcs_offset["HOST_CR4"] * 4
        data = self.address_space.read(offset+off, 0x04)
        cr4 = struct.unpack("<I", data)[0]
        mask = 0x2000
        if (cr4 & mask):
            return True
        else:
            return False

    def skip(self, data, offset):
        return 4096





class VmcsScan(scan.BaseScanner):
    """
    This scanner finds the possible VMCS candidates.
    Use this scanner when you know the microarchitecture.
    """

    checks = [ ("RevisionIdCheck", {}),
               ("SecondEntryCheck", {}),
               ("VMXEnableCheck", {}),
               ("VmcsLinkPointerCheck", {})
               ]



class NestedScan(scan.BaseScanner):
    """
    This scanner finds all the possible nested VMCS memory structures
    layouts.
    This means it finds the VMCS12 and in general VMCS1N.
    """

    checks = [ ("NestedRevisionIdCheck", {}),
               ("SecondEntryCheck", {}),
               ("VMXEnableCheck", {}),
               ("VmcsLinkPointerCheck", {})
               ]



class NestedRevisionIdCheck(scan.ScannerCheck):

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def match_nested_hypervisor(self, rev_id):
        global nvalidated

        nhyper = layouts.db.nested_revision_id_db[rev_id]
        if nhyper == "KVM":
            if nvalidated == 0:
                return layouts.kvm_nested.vmcs
        elif nhyper == "VMware":
            if nvalidated == 0:
                return layouts.vmware_nested.vmcs
        elif nhyper == "Xen":
            if nvalidated == 0:
                return layouts.xen_nested.vmcs
        else:
            return None


    def check(self, offset):
        global vmcs_offset, nvalidated, prev_layout, prev_saved

        data = self.address_space.read(offset, 0x04)
        rev_id = struct.unpack('<I', data)[0]
        if rev_id in layouts.db.nested_revision_id_db.keys():
            nh = self.match_nested_hypervisor(rev_id)
            if nh != None:
                if nvalidated == 0:
                    if prev_saved == 0:
                        prev_layout = vmcs_offset
                        prev_saved = 1
                    vmcs_offset = nh
#                    debug.info("Nested VMCS - [%s]" % layouts.db.nested_revision_id_db[rev_id])
            if vmcs_offset != None:
                return True
        return False


    def skip(self, data, offset):
        return 4096



class GenericSecondEntryCheck(scan.ScannerCheck):
    """
    VMCS Second Entry check
    Second entry must be zero.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        data = self.address_space.read(offset + 0x04, 0x04)
        second_entry = struct.unpack('<I', data)[0]
        if second_entry == 0x00:
            return True
        return False


    def skip(self, data, offset):
        return 4096


class GenericVmcsLinkPointerCheck(scan.ScannerCheck):
    """
    VMCS Link Pointer Property
    Find two consecutive words with the following value 0xffffffff.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        counter = 0
        for f in range(4, 4094, 4):
            try:
                data = self.address_space.read(offset + f, 0x04)
            except:
                continue

            entry = struct.unpack('<I', data)[0]

            if entry != 0xffffffff: continue
            counter += 1

            try:
                next_raw = self.address_space.read(offset + f + 0x04, 0x04)
            except:
                continue

            nexten = struct.unpack('<I', next_raw)[0]
            if nexten != 0xffffffff: continue
            counter += 1

            if counter == 2:
                #debug.info("vmcslinkpointer Propertyty ok at page: %08x" % offset)
                return True
        return False


    def skip(self, data, offset):
        return 4096


class GenericCr3Check(scan.ScannerCheck):
    """
    CR3 generally is 4k aligned.
    Scan the candidate page to find at least two aligned values.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        global generic_vmcs_cr3

        counter = 0
        for f in range(0, 4094, 4):
            try:
                data = self.address_space.read(offset + f, 0x04)
            except:
                continue

            entry = struct.unpack('<I', data)[0]

            if entry == 0x00:
                continue
            if (entry % 4096) == 0:
                counter += 1
                if offset not in generic_vmcs_cr3:
                    generic_vmcs_cr3[offset] = []
                else:
                    generic_vmcs_cr3[offset].append(entry)

        if counter >= 2:
            #debug.info("cr3 aligniment property at %08x" % offset)
            return True
        return False


    def skip(self, data, offset):
        return 4096


class GenericCsSegmentCheck(scan.ScannerCheck):
    """
    Generally there is at least one entry in the VMCS with the CS segment register set at 0x60.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        for f in range(0, 4094, 4):
            try:
                data = self.address_space.read(offset + f, 0x04)
            except:
                continue
            entry = struct.unpack('<I', data)[0]
            if entry != 0x60:
                continue
            #debug.info("cssegment found in page: %08x" % offset)
            return True

        return False


    def skip(self, data, offset):
        return 4096



class GenericSsSegmentCheck(scan.ScannerCheck):
    """
    Generally there is at least one entry in the VMCS with the SS segment register set at 0x68.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)


    def check(self, offset):
        for f in range(0, 4094, 4):
            try:
                data = self.address_space.read(offset + f, 0x04)
            except:
                continue
            entry = struct.unpack('<I', data)[0]
            if entry != 0x68:
                continue
            return True
        return False


    def skip(self, data, offset):
        return 4096



class GenericVmcsScan(scan.BaseScanner):
    """
    This scanner finds the possible VMCS candidates.
    Use this scanner when you don't know the VMCS memory layout.
    """

    checks = [ ("GenericSecondEntryCheck", {}),
               ("GenericVmcsLinkPointerCheck", {}),
               ("GenericCsSegmentCheck", {}),
               ("GenericSsSegmentCheck", {}),
               ("GenericCr3Check", {})
               ]


#class Actaeon(common.AbstractWindowsCommand):
'''
In this way the plugin should be profile independent.
'''
class Hyperls(commands.Command):
    '''
    Detect hypervisors using Intel VT-x technology.
    '''
    def __init__(self, config, *args, **kwargs):
        #common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        commands.Command.__init__(self, config, *args, **kwargs)
        self._config.add_option('ARCH', short_option = 'm', default = None,
            help = 'Intel Microarchitecture (penryn, sandy or westmere)',
            action = 'store', type = 'str')
        self._config.add_option('VERBOSE', short_option = 'v', default = False,
            action = 'store_true', help = 'Verbose output (print VMCS structure)')
        self._config.add_option('GENERIC', short_option = 'G', default = False,
            action = 'store_true', help = 'Use generic heuristics to detect the VMCS')
        self._config.add_option('NESTED', short_option = 'N', default = False,
            action = 'store_true', help = 'Check for nested virtualization')

    # Check Present flag
    def isPagePresent(self, va):
        mask = 0x01
        if (va & mask) == 1:
            return True
        return False

    # Check Page Directory Entry PS flag
    def isExtendedPaging(self, va):
        mask = 0x80
        if ((va & mask) >> 7) == 1:
            return True
        return False

    # Check if the host is in PAE mode
    def isPAE(self, offset, phy_space, ishost):
        if ishost:
            off = vmcs_offset["HOST_CR4"] * 4
        else:
            off = vmcs_offset["GUEST_CR4"] * 4
        data = phy_space.read(offset + off, 0x04)
        cr4 = struct.unpack('<I', data)[0]
        mask = 0x20
        if ((cr4 & mask) >> 5) == 1:
            return True
        return False

    #Check if the host is in IA32E mode, in this case we have 64 bit address space
    def isIA32E(self, offset, phy_space, ishost):
        debug.debug("checking host VM_EXIT_CONTROLS")
        if ishost:
            off = vmcs_offset["VM_EXIT_CONTROLS"] * 4
        else:
            off = vmcs_offset["VM_ENTRY_CONTROLS"] * 4
        data = phy_space.read(offset + off, 0x04)
        vmx_exit_control = struct.unpack('<I', data)[0]
        mask_host_address_space_size = 0x200           # Checking host address space size -> bit 10
        if ((vmx_exit_control & mask_host_address_space_size) >> 9) == 1:
            return True
        return False

    '''
    Pagediralgo - 64 bits - (16 (sign extension) - 9 - 9 - 9 - 9 - 12)
    '''
    def page_dir_validation64(self, page, phy_space):
        global vmcs_offset
        #debug.info("Validation IA-32e")
        cr3_raw = phy_space.read(page + (vmcs_offset["HOST_CR3"]*4), 0x08)
        cr3 = struct.unpack('<Q', cr3_raw)[0]
        mask_cr3 = 0x000FFFFFFFFFF000
        mask_1GB = 0x000FFFFFC0000000
        mask_2MB = 0x000FFFFFFFE00000
        mask_4KB = 0x000FFFFFFFFFF000
        cr3 = cr3 & mask_cr3  # Alignment to 4KB

        #PML4
        for pml4_entry in range(0, 4096, 8):
            pml4e_raw = phy_space.read(cr3 + pml4_entry, 8)
            pml4e = struct.unpack("<Q", pml4e_raw)[0]
            pml4e_addr = pml4e & mask_4KB
            if self.isPagePresent(pml4e) and phy_space.is_valid_address(pml4e_addr):
                #PDPT
                for pdpt_entry in range(0, 4096, 8):
                    pdpte_raw = phy_space.read(pml4e_addr + pdpt_entry, 8)
                    pdpte = struct.unpack("<Q", pdpte_raw)[0]
                    pdpte_addr = pdpte & mask_4KB
                    if self.isPagePresent(pdpte) and phy_space.is_valid_address(pdpte_addr):
                        # 1 GiB pages are not implemented so far, it is quite strange
                        # for an hypervisor to allocate 1 GiB to store VMCS :-)
                        # Often VMCSs are stored in 2MiB page.
                        if self.isExtendedPaging(pdpte):
                            continue
                            #PD
                        for pd_entry in range(0, 4096, 8):
                            pde_raw = phy_space.read(pdpte_addr + pd_entry, 0x08)
                            pde = struct.unpack("<Q", pde_raw)[0]
                            pde_addr = pde & mask_4KB
                            if self.isPagePresent(pde) and phy_space.is_valid_address(pde_addr):
                                if self.isExtendedPaging(pde):
                                    if (pde & mask_2MB) == (page & mask_2MB):
                                        return True
                                else:
                                    #PT
                                    for pt_entry in range(0, 4096, 8):
                                            pte_raw = phy_space.read(pde_addr + pt_entry, 0x08)
                                            pte = struct.unpack("<Q", pte_raw)[0]
                                            if self.isPagePresent(pte):
                                                if (pte & mask_4KB) == (page & mask_4KB):
                                                    return True
        return False

    def page_dir_validation32PAE(self, page, phy_space):
        global vmcs_offset
        mask_cr3 = 0xFFFFFFE0
        mask_2MB = 0x000FFFFFFFE00000
        mask_4KB = 0x000FFFFFFFFFF000

        #debug.info("Validation PAE paging")
        cr3_raw = phy_space.read(page + vmcs_offset["HOST_CR3"] * 4, 4)
        cr3 = struct.unpack("<I", cr3_raw)[0]
        cr3 = cr3 & mask_cr3
        #PDPTEs are 4 x 64 bit
        for entry in range(0, 32, 8):
            pdpte_raw = phy_space.read(cr3+entry, 0x08)
            pdpte = struct.unpack("<Q", pdpte_raw)[0]
            pdpte_addr = pdpte & mask_4KB
            if self.isPagePresent(pdpte) and phy_space.is_valid_address(pdpte_addr):
                #PDEs are 512 x 64 bit each PDPTE_addr is 4KiB aligned
                for pd_entry in range(0, 4096, 8):
                    pde_raw = phy_space.read(pdpte_addr + pd_entry, 0x08)
                    pde = struct.unpack("<Q", pde_raw)[0]
                    pde_addr = pde & mask_4KB
                    #If the Page Size bit is set the the PDE points to 2 MiB physical frame
                    if self.isPagePresent(pde) and phy_space.is_valid_address(pde_addr):
                        if self.isExtendedPaging(pde):                        
                            #Check if the page is in the PDE address space
                            if (pde & mask_2MB) == (page & mask_2MB):
                                return True
                        else:
                            #PTEs are 512 x 64 bit each PDE_addr is 4 KiB aligned
                            for pt_entry in range(0, 4096, 8):
                                pte_raw = phy_space.read(pde_addr + pt_entry, 0x08)
                                pte = struct.unpack("<Q", pte_raw)[0]
                                #Check if the the page is in the PTE address space
                                if self.isPagePresent(pte):
                                    if (pte & mask_4KB) == (page & mask_4KB):
                                        return True
        return False

    def page_dir_validation32(self, page, phy_space):
        '''
        Let's start validating the normal 32 translation
        '''
        global vmcs_offset
        mask_4KB = 0xFFFFF000
        mask_4MB = 0xFFC00000
        #debug.info("Validation 32 bit paging")
        cr3_raw = phy_space.read(page + (vmcs_offset["HOST_CR3"]*4), 4)
        cr3 = struct.unpack('<I', cr3_raw)[0]

        # PD
        for entry in range(0, 4096, 4):
            raw = phy_space.read(cr3 + entry, 0x04)
            pde_raw = struct.unpack('<I', raw)[0]
            pde = pde_raw & mask_4KB
            # Extended present so VA is divided into 2 sections: 31-22 and 21-0
            # first 10 are used as usual :)
            if self.isPagePresent(pde_raw) and phy_space.is_valid_address(pde):
                if self.isExtendedPaging(pde_raw):
                    if (pde_raw & mask_4MB) == (page & mask_4MB):
                        return True
                # PT - Normal translation 10 - 10 - 12
                for off in range(0, 4096, 4):
                    raw = phy_space.read(pde + off, 4)
                    pte_raw = struct.unpack('<I', raw)[0]
                    if self.isPagePresent(pte_raw):
                        if (pte_raw & mask_4KB) == (page & mask_4KB):
                            return True
        return False


    '''
    This function has to be used during the generic detection algorithm.
    From the set of candidate VMCS structures we will check only the ones
    starting with a known revision id.
    '''
    def find_microarch(self, phy_space, page):
        try:
            rev_id_raw = phy_space.read(page, 0x04)
        except:
            return False

        rev_id = struct.unpack('<I', rev_id_raw)[0]
        if rev_id in layouts.db.revision_id_db.keys():
            return True

        return False


    def check_microarch(self, addr, phy_space, key):
        microarch = hyper.revision_id_db[key]

        if microarch.lower() == "sandy":
            vmcs_off = hyper.vmcs_offset_sandy
        elif microarch.lower() == "core":
            vmcs_off = hyper.vmcs_offset_core
        else:
            debug.error("Microarchitecture %s not supported yet." % microarch)

        off = vmcs_off["VMCS_LINK_POINTER"] * 4
        data = phy_space.read(addr + off, 0x04)
        vmcs_link_pointer = struct.unpack('<I', data)[0]
        data2 = phy_space.read(addr + off + 0x04, 0x04)
        vmcs_link_pointer2 = struct.unpack('<I', data2)[0]

        if (vmcs_link_pointer == 0xffffffff and vmcs_link_pointer2 == 0xffffffff):
            size = layouts.vmcs.vmcs_field_size["GUEST_CR3"] / 8
            off = vmcs_off["GUEST_CR3"] * 4
            data = phy_space.read(addr + off, size)
            if size == 4:
                guest_cr3 = struct.unpack('<I', data)[0]
            elif size == 8:
                guest_cr3 = struct.unpack('<Q', data)[0]
            else:
                debug.error("CR3 size not possible.")

            if ((guest_cr3 % 4096) == 0) and (guest_cr3 != 0):
                debug.info("\t|__ VMCS 0x%08x [CONSISTENT]" % addr)


    def find_prevalent_microarch(self, generic_vmcs, phy_space):
        microarch_vmcs = {}
        for vmcs in generic_vmcs:
            try:
                revid_raw = phy_space.read(vmcs, 0x04)
            except:
                continue

            rev_id = struct.unpack('<I', revid_raw)[0]
            for key in layouts.revision_id_db.keys():
                if key == rev_id:
                    if key not in microarch_vmcs:
                        microarch_vmcs[key] = []
                        microarch_vmcs[key].append(vmcs)
                        debug.info("Possible VMCS 0x%x with %s microarchitecture" % (vmcs,
                        layouts.db.revision_id_db[key]))
                        self.check_microarch(vmcs, phy_space, key)
                    else:
                        debug.info("Possible VMCS 0x%x with %s microarchitecture" % (vmcs,
                        layouts.db.revision_id_db[key]))
                        microarch_vmcs[key].append(vmcs)
                        self.check_microarch(vmcs, phy_space, key)
        maxi = 0
        key = None
        for k, v in microarch_vmcs.items():
            if len(microarch_vmcs[k]) > maxi:
                maxi = len(microarch_vmcs[k])
                key = k
        if key != None:
            debug.info("Prevalent Microarch: [0x%08x - %s] - VMCS: %d" % (key,
            layouts.db.revision_id_db[key], maxi))
        debug.info("Microarchitecture not found.")


    def match_nested_hypervisor(self, rev_id):
        nhyper = layouts.db.nested_revision_id_db[rev_id]
        if nhyper == "KVM":
            return layouts.kvm_nested.vmcs
        elif nhyper == "VMware":
            return layouts.vmware_nested.vmcs
        elif nhyper == "Xen":
            return layouts.xen_nested.vmcs
        else:
            return None


    def calculate(self):
        global vmcs_offset, revision_id, memory, vmcs12, nvalidated

        if self._config.GENERIC == False:
            if self._config.ARCH in layouts.db.microarch_db:
                revision_id = layouts.db.microarch_db[self._config.ARCH]
                if self._config.ARCH == "penryn":
                    vmcs_offset = layouts.penryn.vmcs
                elif self._config.ARCH == "sandy":
                    vmcs_offset = layouts.sandy.vmcs
                elif self._config.ARCH == "westmere":
                    vmcs_offset = layouts.westmere.vmcs
            else:
                debug.error("Intel Microarchitecture not valid. Current supported microarchitectures: penryn, sandy, westmere")

        phy_space = utils.load_as(self._config, astype = 'physical')
        memory = phy_space
        debug.debug("Debug Mode")
        if self._config.GENERIC == False:
            for offset in VmcsScan().scan(phy_space):
                debug.info(">> Possible VMCS at 0x%x" % offset)
                if not self.isPAE(offset, phy_space, True):
                    # 32 bit paging 
                    if self.page_dir_validation32(offset, phy_space):
                        debug.info("[32 bit] VMCS 0x%x has been validated" % offset)
                        hyper.vmcs_found.append(offset)
                        yield offset
                    else:
                        debug.info("[32 bit] VMCS 0x%x has not been validated" % offset)
                elif not self.isIA32E(offset, phy_space, True):
                    # 32 bit PAE paging
                    if self.page_dir_validation32PAE(offset, phy_space):
                        debug.info("[32 bit PAE] VMCS 0x%x has been validated" % offset)
                        hyper.vmcs_found.append(offset)
                        yield offset
                    else:
                        debug.info("[32 bit PAE] VMCS 0x%x has not been validate" % offset)
                elif self.isIA32E(offset, phy_space, True) and self.isPAE(offset, phy_space, True):
                    # IA32E paging
                    if self.page_dir_validation64(offset, phy_space):
                        debug.info("[64 bit] VMCS 0x%x has been validated" % offset)
                        hyper.vmcs_found.append(offset)
                        yield offset
                    else:
                        debug.info("[64 bit] VMCS 0x%x has not been validated" % offset)
                else:
                    debug.info("Not possible to validate the VMCS. Impossible to detect paging")

            if self._config.NESTED:
                priv_cr3_list = []
                for vm in hyper.vmcs_found:
                    cr3_raw = phy_space.read(offset + (vmcs_offset["HOST_CR3"]*4), 4)
                    cr3 = struct.unpack('<I', cr3_raw)[0]
                    priv_cr3_list.append(cr3)

                '''
                TODO: Make validation more generic for nested VMCS
                '''
                val = 0
                for offset in NestedScan().scan(phy_space):
                    rev_id = self.get_vmcs_field(offset, 0, 4)
                    debug.info("Possible Nested VMCS at 0x%08x - [%s]" % (offset, layouts.db.nested_revision_id_db[rev_id]))
                    nvalidated = 1
                    for hpd in priv_cr3_list:
                        if self.page_dir_validation32(offset, phy_space, hpd):
                            val = 1
                            hyper.nvmcs_found.append(offset)
                        if val == 0:
                            if self.page_dir_validation64(offset, phy_space):
                                val = 1
                                hyper.nvmcs_found.append(offset)
                        val = 0
                    nh = self.match_nested_hypervisor(rev_id)
                    if nh != None:
                        vmcs12 = nh
        '''
        GENERIC Scan - Very slow (due to the validation)
        '''
        if self._config.GENERIC == True:
            generic_vmcs = []
            for offset in GenericVmcsScan().scan(phy_space):
                if self.find_microarch(phy_space, offset):
                    if self._config.VERBOSE:
                        debug.info("Candidate VMCS at 0x%08x" % offset)
                    generic_vmcs.append(offset)

            self.find_prevalent_microarch(generic_vmcs,phy_space)


    def get_vmcs_field(self, address, offset, size):
        global memory

        raw = memory.read(address + offset, size)

        if size == 4:
            return struct.unpack('<I', raw)[0]
        elif size == 2:
            return struct.unpack('<H', raw)[0]
        elif size == 8:
            return struct.unpack('<Q', raw)[0]
        else:
            return 0


    def get_exception_bitmap_bit(self, outfd, exception_bitmap):
        for k, v in layouts.vmcs.exception_bitmap_bits.items():
            tmp = exception_bitmap >> k
            bit = tmp & 1
            if bit == 1:
                outfd.write("\t\t|_ %s : %d\n" % (v, k))


    def parsing_pin_based_controls(self, outfd, word):
        for k, v in layouts.vmcs.pin_based_execution_controls.items():
            if ((word >> k) & 0x01) == 1:
                outfd.write("\t\t|_ %s\n" % v)

    def parsing_vmexit_controls(self, outfd, word):
        for k, v in layouts.vmcs.vmexits_control.items():
            if ((word >> k) & 0x01) == 1:
                outfd.write("\t\t|_ %s\n" % v)

    def parsing_processor_based_controls(self, outfd, word):
        for k, v in layouts.vmcs.processor_based_execution_controls.items():
            if k == 25 and ((word >> k) & 0x01) == 1:
                    hyper.iobitmaps = 1
            if k == 31 and ((word >> k) & 0x01) == 1:
                    hyper.use_secondary_control = 1
            if ((word >> k) & 0x01) == 1:
                    outfd.write("\t\t|_ %s\n" % v)
            if k == 28 and ((word >> k) & 0x01) == 1:
                    hyper.use_msr_bitmaps = 1


    def check_cr3(self, outfd, target_count):
        if target_count == 0:
            outfd.write("\t\t|_ MOV to CR3 always causes a VM exit.\n")
        if target_count > 4:
            outfd.write("\t\t|_ Not possible... VM entry will fail.\n")


    def parse_iobitmaps(self, outfd):
        global memory

        outfd.write("\t\t|_ IO Bitmap A at 0x%08x\n" % hyper.iobitmapa)
        if (hyper.iobitmapa % 4096) == 0:
            a_counter = 0
            for i in range(0, 4096):
                    raw = memory.read(hyper.iobitmapa + i, 0x01)
                    port = ord(raw)
                    for j in range(0, 8):
                            if (port >> j) & 0x1 != 0: a_counter += 1
            outfd.write("\t\t\t|_ %d ports cause a VMEXIT\n" % a_counter)

        outfd.write("\t\t|_ IO Bitmap B at 0x%08x\n" % hyper.iobitmapb)
        if (hyper.iobitmapa % 4096) == 0:
            b_counter = 0
            for i in range(0, 4096):
                raw = memory.read(hyper.iobitmapb + i, 0x01)
                port = ord(raw)
                for j in range(0, 8):
                    if (port >> j) & 0x1 != 0: b_counter += 1
            outfd.write("\t\t\t|_ %d ports cause a VMEXIT\n" % b_counter)

    # Intel Manual - Vol. 3 21-3
    def check_clts_exit(self, outfd, address):
        global vmcs_offset

        size = layouts.vmcs.vmcs_field_size["CR0_GUEST_HOST_MASK"] / 8
        outfd.write("\t|_ CLTS check:\n")
        cr0_guest_host_mask = self.get_vmcs_field(address, vmcs_offset["CR0_GUEST_HOST_MASK"]*4, size)

        size = layouts.vmcs.vmcs_field_size["CR0_READ_SHADOW"] / 8
        cr0_read_shadow = self.get_vmcs_field(address, vmcs_offset["CR0_READ_SHADOW"]*4, size)

        if ((cr0_guest_host_mask >> 3) & 0x01) == 1 and ((cr0_read_shadow >> 3) & 0x01) == 1:
            outfd.write("\t\t|_ CLTS instruction will cause a VMEXIT\n")


    def check_rdmsr(self, outfd, address):
        outfd.write("\t|_ RDMSR check:\n")
        if hyper.use_msr_bitmaps == 0:
            outfd.write("\t\t|_ RDMSR instruction will cause a VMEXIT\n")
        else:
            outfd.write("\t\t|_ Not enough information (I need RCX).\n")


    def check_wrmsr(self, outfd, address):
        outfd.write("\t|_ WRMSR check:\n")
        if hyper.use_msr_bitmaps == 0:
            outfd.write("\t\t|_ WRMSR instruction will cause a VMEXIT\n\n")
        else:
            outfd.write("\t\t|_ Not enough information (I need RCX).\n\n")


    def parsing_secondary_vm_exec_control(self, outfd, word, address):
        for k, v in layouts.vmcs.secondary_exec_controls.items():
            if ((word >> k) & 0x01) == 1:
                outfd.write("\t\t|_ %s\n" % v)

    def eptPageAccessAllowed(self, page):
        mask = 0x07
        mask_4KB = 0x000FFFFFFFFFF000
        if (page & mask) > 0x00 and (page & mask_4KB) > 0x00:
            return True
        else:
            return False

    def walkEPTtoCountGuests(self, vmcs_list):
        global memory

        guests = {}
        physical_pages = {}

        for vmcs in vmcs_list:
            eptp = self.get_vmcs_field(vmcs, vmcs_offset["EPT_POINTER"] * 4, layouts.vmcs.vmcs_field_size["EPT_POINTER"] / 8)
            debug.debug("VMCS: 0x%x EPT: 0x%x physical_pages len = %d len VMCS list %d" % (vmcs, eptp, len(physical_pages), len(vmcs_list)))
            mask_eptp = 0x000FFFFFFFFFF000
            mask_1GB = 0x000FFFFFC0000000
            mask_2MB = 0x000FFFFFFFE00000
            mask_4KB = 0x000FFFFFFFFFF000
            eptp = eptp & mask_eptp  # Alignment to 4KB
            if not memory.is_valid_address(eptp):
                continue
            found = False
            #PML4
            for pml4_entry in range(0, 4096, 8):
                if found:
                    break
                pml4e_raw = memory.read(eptp + pml4_entry, 8)
                pml4e = struct.unpack("<Q", pml4e_raw)[0]
                pml4e_addr = pml4e & mask_4KB
                if self.eptPageAccessAllowed(pml4e) and memory.is_valid_address(pml4e_addr):
                    #PDPT
                    for pdpt_entry in range(0, 4096, 8):
                        if found:
                            break
                        pdpte_raw = memory.read(pml4e_addr + pdpt_entry, 8)
                        pdpte = struct.unpack("<Q", pdpte_raw)[0]
                        pdpte_addr = pdpte & mask_4KB
                        if self.eptPageAccessAllowed(pdpte) and memory.is_valid_address(pdpte_addr):
                            if self.isExtendedPaging(pdpte):
                                pdpte_addr = pdpte_addr & mask_1GB
                                if pdpte_addr in physical_pages:
                                    if not vmcs in guests[physical_pages[pde_addr]]:
                                        guests[physical_pages[pdpte_addr]].append(vmcs)
                                        found = True
                                        debug.debug("Match 1GB VMCS 0x%x with physical 0x%x to GUEST 0x%x" % (vmcs, pdpte_addr, physical_pages[pdpte_addr]))
                                else:
                                    physical_pages[pdpte_addr] = vmcs
                                    if not vmcs in guests:
                                        guests[vmcs] = [vmcs]
                                    debug.debug("Added 1GB VMCS 0x%x with physical 0x%x to GUEST 0x%x" % (vmcs, pdpte_addr, physical_pages[pdpte_addr]))
                            elif not found:
                                #PD
                                for pd_entry in range(0, 4096, 8):
                                    if found:
                                        break
                                    pde_raw = memory.read(pdpte_addr + pd_entry, 0x08)
                                    pde = struct.unpack("<Q", pde_raw)[0]
                                    pde_addr = pde & mask_4KB
                                    if self.eptPageAccessAllowed(pde) and memory.is_valid_address(pde_addr):
                                        if self.isExtendedPaging(pde):
                                            pde_addr = pde & mask_2MB
                                            if pde_addr in physical_pages:
                                                if not vmcs in guests[physical_pages[pde_addr]]:
                                                    guests[physical_pages[pde_addr]].append(vmcs)
                                                    found = True
                                                    debug.debug("Match 2MB VMCS 0x%x with physical 0x%x to GUEST 0x%x" % (vmcs, pde_addr, physical_pages[pde_addr]))
                                            else:
                                                physical_pages[pde_addr] = vmcs
                                                if not vmcs in guests:
                                                    guests[vmcs] = [vmcs]
                                                debug.debug("Added 2MB VMCS 0x%x with physical 0x%x to GUEST 0x%x" % (vmcs, pde_addr, physical_pages[pde_addr]))
                                        elif not found:
                                            #PT
                                            for pt_entry in range(0, 4096, 8):
                                                    if found:
                                                        break
                                                    pte_raw = memory.read(pde_addr + pt_entry, 0x08)
                                                    pte = struct.unpack("<Q", pte_raw)[0]
                                                    pte_addr = pte & mask_4KB
                                                    if self.eptPageAccessAllowed(pte) and memory.is_valid_address(pte_addr):
                                                        if pte_addr in physical_pages:
                                                            if not vmcs in guests[physical_pages[pte_addr]]:
                                                                guests[physical_pages[pte_addr]].append(vmcs)
                                                                found = True
                                                                debug.debug("Match 4KB VMCS 0x%x with physical 0x%x to GUEST 0x%x" % (vmcs, pte_addr, physical_pages[pte_addr]))

                                                        else:
                                                            physical_pages[pte_addr] = vmcs
                                                            if not vmcs in guests:
                                                                guests[vmcs] = [vmcs]
                                                            debug.debug("Added 4KB VMCS 0x%x with physical 0x%x to GUEST 0x%x" % (vmcs, pte_addr, physical_pages[pte_addr]))
        return guests

    def useAPICtoCountGuests(self, vmcs_list):
        guests = {}
        for vmcs in vmcs_list:
            apic_addr = self.get_vmcs_field(vmcs, vmcs_offset["APIC_ACCESS_ADDR"] * 4, layouts.vmcs.vmcs_field_size["APIC_ACCESS_ADDR"] / 8)
            if apic_addr == 0x00:
                continue
            if apic_addr in guests:
                guests[apic_addr].append(vmcs)
            else:
                guests[apic_addr] = [vmcs]
        return guests


    def countGuests(self, outfd):
        global vmcs_offset, memory
        outfd.write("\n:: Counting Guests in dump...\n")
        outfd.write(">> Via EPT ")
        if "EPT_POINTER" in vmcs_offset:
            guests = self.walkEPTtoCountGuests(hyper.vmcs_found)
            if len(guests.keys()) != 0:
                outfd.write(" [OK]\n")
            else:
                outfd.write(" [FAIL]\n")
        else:
            outfd.write(" [FAIL]\n")
            outfd.write(">> Via APIC ")
            guests = self.useAPICtoCountGuests(hyper.vmcs_found)
            if len(guests.keys()) != 0:
                outfd.write(" [OK]\n")
        i = 1
        for guest, vmcs_list in guests.items():
            if guest == 0x00 and not "EPT_POINTER" in vmcs_offset:
                outfd.write("\t\t>> Not possible to count Guests\n")
                continue
            else:
                outfd.write("\t\t|_ Guest %d used %d core:\n" % (i, len(vmcs_list)))
                i += 1
            for vmcs in vmcs_list:
                outfd.write("\t\t - VMCS address: {0:#0{1}x}\n".format(vmcs, 18))


    def count_hypervisors(self, outfd):
        global vmcs12

        outfd.write("\n:: Counting the hypervisors in the dump...\n")
        rip = {}
        for v in set(hyper.vmcs_found):
            size = layouts.vmcs.vmcs_field_size["HOST_RIP"] / 8
            ip = self.get_vmcs_field(v, vmcs_offset["HOST_RIP"]*4, size)
            if ip not in rip:
                rip[ip] = 0
            else:
                rip[ip] += 1
        for v in set(hyper.nvmcs_found):
            size = layouts.vmcs.vmcs_field_size["HOST_RIP"] / 8
            ip = self.get_vmcs_field(v, vmcs12["HOST_RIP"]*4, size)
            if ip not in rip:
                rip[ip] = 0
            else:
                rip[ip] += 1
        list_rip = rip.keys()
        outfd.write("\t|_ There are %d hypervisors: " % len(list_rip))
        for i in list_rip:
            outfd.write(" 0x%08x " % i)
        outfd.write("\n")


    '''
    From the set of VMCS0N and VMCS1N it tries to figure out, who is who.
    This means to discover from the VMCS0N set which VMCS is the the VMCS01 and so on.
    TODO: more generic. Current limitation only able to understand one level on nested.
    '''
    def hierarchy_check(self, outfd):
        global vmcs_offset, vmcs12, prev_layout

        outfd.write("\n:: Hierarchy check...\n")
        outfd.write("\t|_ Looking for the VMCS01...\n")
        
        # restoring the previous_layout - overwritten during the nested scan
        vmcs_offset = prev_layout

        for v in set(hyper.vmcs_found):
            size = layouts.vmcs.vmcs_field_size["GUEST_CR3"] / 8
            gcr3 = self.get_vmcs_field(v, vmcs_offset["GUEST_CR3"]*4, size)
            for nv in set(hyper.nvmcs_found):
                size = layouts.vmcs.vmcs_field_size["HOST_CR3"] / 8
                nhcr3 = self.get_vmcs_field(nv, vmcs12["HOST_CR3"]*4, size)
                if gcr3 == nhcr3:
                    outfd.write("\t\t|_ VMCS01 at 0x%08x\n" % v)

        outfd.write("\t|_ Looking for VMCS02...\n")
        for v in set(hyper.vmcs_found):
            size = layouts.vmcs.vmcs_field_size["GUEST_CR3"] / 8
            gcr3 = self.get_vmcs_field(v, vmcs_offset["GUEST_CR3"]*4, size)
            for nv in set(hyper.nvmcs_found):
                size = layouts.vmcs.vmcs_field_size["GUEST_CR3"] / 8
                ngcr3 = self.get_vmcs_field(nv, vmcs12["GUEST_CR3"]*4, size)
                if gcr3 == ngcr3:
                    outfd.write("\t\t|_ VMCS02 at 0x%08x\n" % v)



    def render_text(self, outfd, data):
            global vmcs_offset, memory
            debug.debug("debug mode")
            outfd.write("\n:: Looking for VMCS0N...\n")
            for i in data:
                    if "EPT_POINTER" in vmcs_offset:
                        outfd.write("\t|_ VMCS at {0:#0{1}x} - EPTP: {2:#0{3}x}\n"
                        .format(i,18,self.get_vmcs_field(i, vmcs_offset["EPT_POINTER"] * 4, 0x08),18))
                    else:
                        outfd.write("\t|_ VMCS at {0:#0{1}x}\n".format(i,18))
                    if self._config.VERBOSE:
                        address = i
                        for k,v in vmcs_offset.items():
                            off = v * 4
                            size = layouts.vmcs.vmcs_field_size[k] / 8
                            if k == "VM_EXIT_REASON":
                                outfd.write("\t|_ %s : 0x%08x - %s\n" % (k, self.get_vmcs_field(address, off, size), layouts.vmcs.vmexits[self.get_vmcs_field(address, off, size)]))
                            elif k == "EXCEPTION_BITMAP":
                                bitmap = self.get_vmcs_field(address, off, size)
                                outfd.write("\t|_ %s : 0x%08x - %s\n"   % (k, bitmap, bin(bitmap)))
                                self.get_exception_bitmap_bit(outfd, bitmap)
                            elif k == "PIN_BASED_VM_EXEC_CONTROL":
                                pinexec = self.get_vmcs_field(address, off, size)
                                outfd.write("\t|_ %s: 0x%08x - %s\n" % (k, pinexec, bin(pinexec)))
                                self.parsing_pin_based_controls(outfd, pinexec)
                            elif k == "CPU_BASED_VM_EXEC_CONTROL":
                                procexec = self.get_vmcs_field(address, off, size)
                                outfd.write("\t|_ %s: 0x%08x - %s\n" % (k, procexec, bin(procexec)))
                                self.parsing_processor_based_controls(outfd, procexec)
                            elif k == "CR3_TARGET_COUNT":
                                outfd.write("\t|_ %s : 0x%08x\n"   % (k, self.get_vmcs_field(address, off, size)))
                                self.check_cr3(outfd, self.get_vmcs_field(address, off, size))
                            elif k == "VM_EXIT_CONTROLS":
                                outfd.write("\t|_ %s : 0x%08x\n"   % (k, self.get_vmcs_field(address, off, size)))
                                self.parsing_vmexit_controls(outfd, self.get_vmcs_field(address, off, size))
                            else:
                                outfd.write("\t|_ %s : 0x%x\n" % (k, self.get_vmcs_field(address, off, size)))
                                if k == "IO_BITMAP_A":
                                    hyper.iobitmapa = self.get_vmcs_field(address, off, size)
                                if k == "IO_BITMAP_B":
                                    hyper.iobitmapb = self.get_vmcs_field(address, off, size)
                                if k == "SECONDARY_VM_EXEC_CONTROL" and hyper.use_secondary_control == 1:
                                    self.parsing_secondary_vm_exec_control(outfd, self.get_vmcs_field(address,
                                    off, size), address)
                        if hyper.iobitmaps == 1:
                            outfd.write("\t|_ Zoom on IO_BITMAPS:\n")
                            self.parse_iobitmaps(outfd)
                        self.check_clts_exit(outfd, address)
                        self.check_rdmsr(outfd, address)
                        self.check_wrmsr(outfd, address)
                        outfd.write("\t==========================\n")
            if self._config.NESTED:
                outfd.write("\n:: Looking for VMCS1N...\n")
                for nest in set(hyper.nvmcs_found):
                    outfd.write("\t|_ Nested VMCS at 0x%08x\n" % nest)
                self.hierarchy_check(outfd)
            self.count_hypervisors(outfd)
            self.countGuests(outfd)




config = conf.ConfObject()
config.add_option("EPT", default = None, type = 'int',
                  short_option = 'e', nargs = 1,
                  action = 'store',
                  help = "EPT pointer from VMCS")
