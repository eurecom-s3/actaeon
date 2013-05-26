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



# Table 20-5. Definition of Pin Based VM-Execution Controls.
# Bit Position | Name
pin_based_execution_controls = { 
0 : "External_Interrupt_Exiting",
3 : "NMI_Exiting",
5 : "Virtual_NMIs"
}


# Table 20-6. Definitions of Primary Processor Based VM Execution Controls
# Bit Position | Name
processor_based_execution_controls = { 
2 : "Interrupt_Window_Exiting",
3 : "Use TSC offsetting",
7 : "HLT_Exiting",
9 : "INVLPG_Exiting",
10: "MWAIT_Exiting",
11: "RDPMC_Exiting",
12: "RDTSC_Exiting",
19: "CR8_Load_Exiting",
20: "CR8_Store_Exiting",
21: "Use_TPR_Shadow",
22: "NMI_Window_Exiting",
23: "MOV_DR_Exiting",
24: "Uncondition_IO_Exiting",
25: "Use_IO_Bitmaps",
28: "Use_MSR_Bitmaps",
29: "MONITOR_Exiting",
30: "PAUSE_Exiting",
31: "Activate_Secondary_Controls"
}


# Table 21-7. Definitions of Secondary Processor Based VM Execution Controls.
secondary_exec_controls = {
0 : "Virtualize APIC accesses",
1 : "EPT Enabled",
2 : "Descriptor Table exiting",
3 : "Enable RDTSCP",
4 : "Virtualize x2APIC mode",
5 : "VPID Enabled",
6 : "WBINVD exiting",
7 : "Unrestricted Guest",
10: "PAUSE-Loop Exiting"
}


exception_bitmap_bits = {
0  : "TRAP_DIVIDE_ERROR",
1  : "TRAP_DEBUG",
2  :  "TRAP_NMI",
3  : "TRAP_INT3",
4  : "TRAP_OVERFLOW",
5  : "TRAP_BOUNDS",
6  : "TRAP_INVALID_OP",
7  : "TRAP_NO_DEVICE",
8  : "TRAP_DOUBLE_FAULT",
9  : "TRAP_COPRO_SEG",
10 : "TRAP_INVALID_TSS",
11 : "TRAP_NO_SEGMENT",
12 : "TRAP_STACK_ERROR",
13 : "TRAP_GP_FAULT",
14 : "TRAP_PAGE_FAULT",
15 : "TRAP_SPURIOUS_INT",
16 : "TRAP_COPRO_ERROR",
17 : "TRAP_ALIGNMENT_CHECK",
18 : "TRAP_MACHINE_CHECK",
19 : "TRAP_SIMD_ERROR",
31 : "TRAP_DEFERRED_NMI"
}

vmexits_control = {
    2: "Save debug controls",
    9: "Host address-space size",
    12: "Load IA32_PERF_GLOB AL_CTRL",
    15: "Acknowledge interrupt on exit",
    18: "Save IA32_PAT",
    19: "Load IA32_PAT",
    20: "Save IA32_EFER",
    21: "Load IA32_EFER",
    22: "Save VMX-preemption timer value"
}

vmexits = { 
0 : "Exception or non-maskable interrupt",
1 : "External interrupt",
2 : "Triple fault",
3 : "INIT signal",
4 : "Start-up IPI (SIPI)",
5 : "I/O system-management interrupt (SMI)",
6 : "Other SMI",
7 : "Interrupt window",
8 : "NMI window",
9 : "Task switch",
10 : "CPUID",
11 : "GETSEC",
12 : "HLT",
13 : "INVD",
14 : "INVLPG",
15 : "RDPMC",
16 : "RDTSC",
17 : "RSM",
18 : "VMCALL",
19 : "VMCLEAR",
20 : "VMLAUNCH",
21 : "VMPTRLD",
22 : "VMPTRST",
23 : "VMREAD",
24 : "VMRESUME",
25 : "VMWRITE",
26 : "VMXOFF",
27 : "VMXON",
28 : "Control-register accesses",
29 : "MOV DR",
30 : "I/O instruction",
31 : "RDMSR",
32 : "WRMSR",
33 : "VM-entry failure due to invalid guest state",
34 : "VM-entry failure due to MSR loading",
36 : "MWAIT",
37 : "Monitor trap flag",
39 : "MONITOR",
40 : "PAUSE",
41 : "VM-entry failure due to machine check",
43 : "TPR below threshold"
}


vmcs_field_size = {
"REVISION_ID" : 32,
"ADDRESS_MSR_BITMAPS" : 32,
"VM_EXIT_MSR_STORE_ADDR" : 64,
"ADDRESS_MSR_BITMAPS_HIGH" : 32,
"VM_EXIT_MSR_STORE_ADDR_HIGH" : 32,
"VM_EXIT_MSR_LOAD_ADDR" : 32,
"VM_EXIT_MSR_LOAD_ADDR_HIGH" : 32,
"VM_ENTRY_MSR_LOAD_ADDR" : 32,
"VM_ENTRY_MSR_LOAD_ADDR_HIGH" : 32,
"VIRTUAL_APIC_PAGE_ADDR" : 32,
"VIRTUAL_APIC_PAGE_ADDR_HIGH" : 32,
"APIC_ACCESS_ADDR" : 32,
"APIC_ACCESS_ADDR_HIGH" : 32,
"EXECUTIVE_VMCS_POINTER" : 32,
"EXECUTIVE_VMCS_POINTER_HIGH" : 32,
"EXCEPTION_BITMAP" : 32,
"VM_EXIT_REASON" : 32,
"EXIT_QUALIFICATION" : 64,
"VMX_INSTRUCTION_INFO" : 32,
"VM_EXIT_INTR_INFO" : 32,
"VM_EXIT_INTR_ERROR_CODE" : 32,
"IDT_VECTORING_INFO_FIELD" : 32,
"IDT_VECTORING_ERROR_CODE" : 32,
"VM_EXIT_INSTRUCTION_LEN" : 32,
"VM_EXIT_INSTRUCTION_INFO" : 32,
"SECONDARY_VM_EXEC_CONTROL" : 32,
"GUEST_SMBASE" : 32,
"VM_ENTRY_EXCEPTION_ERROR_CODE" : 32,
"VM_ENTRY_INSTRUCTION_LENGTH" : 32,
"TPR_THRESHOLD" : 32,
"HOST_IA32_PERF_GLOBAL_CTRL" : 32,
"HOST_IA32_PERF_GLOBAL_CTRL_HIGH" : 32,
"CR0_GUEST_HOST_MASK" : 64,
"CR4_GUEST_HOST_MASK" : 64,
"CR0_READ_SHADOW" : 64,
"CR4_READ_SHADOW" : 64,
"IO_RCX" : 64,
"IO_RSI" : 64,
"IO_RDI" : 64,
"IO_RIP" : 64,
"GUEST_LINEAR_ADDRESS" : 64,
"GUEST_CS_SELECTOR" : 16,
"GUEST_SS_SELECTOR" : 16,
"GUEST_ES_SELECTOR" : 16,
"GUEST_FS_SELECTOR" : 16,
"GUEST_GS_SELECTOR" : 16,
"GUEST_LDTR_LDTR" : 16,
"GUEST_TR_SELECTOR" : 16,
"HOST_CS_SELECTOR" : 16,
"HOST_SS_SELECTOR" : 16,
"HOST_DS_SELECTOR" : 16,
"HOST_ES_SELECTOR" : 16,
"HOST_FS_SELECTOR" : 16,
"HOST_GS_SELECTOR" : 16,
"HOST_TR_SELECTOR" : 16,
"VMCS_LINK_POINTER" : 32,
"VMCS_LINK_POINTER_HIGH" : 32,
"GUEST_IA32_DEBUGCTL" : 32,
"GUEST_IA32_DEBUGCTL_HIGH" : 32,
"PIN_BASED_VM_EXEC_CONTROL" : 32,
"CPU_BASED_VM_EXEC_CONTROL" : 32,
"IO_BITMAP_A_HIGH" : 32,
"IO_BITMAP_A" : 32,
"IO_BITMAP_B_HIGH" : 32,
"IO_BITMAP_B" : 32,
"TSC_OFFSET" : 32,
"TSC_OFFSET_HIGH" : 32,
"PAGE_FAULT_ERROR_CODE_MASK" : 32,
"PAGE_FAULT_ERROR_CODE_MATCH" : 32,
"CR3_TARGET_COUNT" : 32,
"CR3_TARGET_VALUE0" : 64,
"CR3_TARGET_VALUE1" : 64,
"CR3_TARGET_VALUE2" : 64,
"CR3_TARGET_VALUE3" : 64,
"VM_EXIT_CONTROLS" : 32,
"VM_ENTRY_CONTROLS" : 32,
"VM_EXIT_MSR_STORE_COUNT" : 32,
"VM_EXIT_MSR_LOAD_COUNT" : 32,
"VM_ENTRY_MSR_LOAD_COUNT" : 32,
"VM_ENTRY_INTR_INFO_FIELD" : 32,
"GUEST_CS_LIMIT" : 32,
"GUEST_SS_LIMIT" : 32,
"GUEST_DS_LIMIT" : 32,
"GUEST_ES_LIMIT" : 32,
"GUEST_FS_LIMIT" : 32,
"GUEST_GS_LIMIT" : 32,
"GUEST_LDTR_LIMIT" : 32,
"GUEST_TR_LIMIT" : 32,
"GUEST_GDTR_LIMIT" : 32,
"GUEST_IDTR_LIMIT" : 32,
"GUEST_DR7" : 64,
"GUEST_INTERRUPTIBILITY_INFO" : 32,
"GUEST_ACTIVITY_STATE" : 32,
# ACCESS RIGHTS 32 bits
#"GUEST_CS_AR_BYTES" : 0x8b000000,
#"GUEST_DS_AR_BYTES" : 0x97000000,
#"GUEST_SS_AR_BYTES" : 0x91000000,
#"GUEST_ES_AR_BYTES" : 0x85000000,
#"GUEST_FS_AR_BYTES" : 0x9d000000,
#"GUEST_GS_AR_BYTES" : 0xa3000000,
#"GUEST_LDTR_AR_BYTES" : 0xa9000000,
#"GUEST_TR_AR_BYTES" : 0xaf000000,
"GUEST_SYSENTER_CS" : 32,
"GUEST_CR0" : 64,
"GUEST_CR3" : 64,
"GUEST_CR4" : 64,
"GUEST_CS_BASE" : 64,
"GUEST_SS_BASE" : 64,
"GUEST_DS_BASE" : 64,
"GUEST_ES_BASE" : 64,
"GUEST_FS_BASE" : 64,
"GUEST_GS_BASE" : 64,
"GUEST_LDTR_BASE" : 64,
"GUEST_TR_BASE" : 64,
"GUEST_GDTR_BASE" : 64,
"GUEST_IDTR_BASE" : 64,
"GUEST_RFLAGS" : 64,
"GUEST_SYSENTER_ESP" : 64,
"GUEST_SYSENTER_EIP" : 64,
"GUEST_IA32_EFER_FULL" : 64,
"HOST_CR0" : 64,
"HOST_CR3" : 64,
"HOST_CR4" : 64,
"HOST_FS_BASE" : 64,
"HOST_GS_BASE" : 64,
"HOST_TR_BASE" : 64,
"HOST_GDTR_BASE" : 64,
"HOST_IDTR_BASE" : 64,
"HOST_IA32_SYSENTER_ESP" : 64,
"HOST_IA32_SYSENTER_EIP" : 64,
"HOST_IA32_EFER_FULL" : 64,
"HOST_IA32_SYSENTER_CS" : 32,
"GUEST_RSP" : 64,
"GUEST_RIP" : 64,
"HOST_RSP" : 64,
"HOST_RIP" : 64,
"EPT_POINTER" : 64,
"EPT_POINTER_HIGH" : 32,
"PDPTE0" : 64,
"PDPTE0_HIGH" :32,
"PDPTE1" : 64,
"PDPTE1_HIGH" : 32,
"PDPTE2" : 64,
"PDPTE2_HIGH" : 32,
"PDPTE3" : 64,
"PDPTE3_HIGH" : 32,
"VPID" : 16
}
