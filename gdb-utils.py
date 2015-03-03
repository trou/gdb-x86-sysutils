import gdb
import struct
import sys
from os.path import dirname

sys.path.append(dirname(__file__))

from intel_sys_structs import *

class SysCommand(gdb.Command):
    "Commands for System data parsing"

    def __init__ (self):
        super (SysCommand, self).__init__ ("sys",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

class GdtDumpCommand(gdb.Command):
    "Dump GDT to console"

    def __init__ (self):
        super (GdtDumpCommand, self).__init__ ("sys gdt",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    # TODO : add limit
    def invoke (self, arg, from_tty):
        args = arg.split(" ")
        ad = long(args[0], 0)
        inf = gdb.selected_inferior()
        for i in range(0, 4096):
            desc = struct.unpack("<Q", inf.read_memory(ad+i*8, 8))[0]
            if desc != 0:
                s = segment_desc(desc)
                print "#%04d : %016x : %s" % (i, desc, s)
                if s.is_tss() and len(args)>1 and args[1] == "-t":
                    try:
                        tss = tss_data(sex='<', wsize=32).unpack(inf.read_memory(s.base, 102))
                        if tss.eip != 0:
                            print "    "+str(tss)
                    except:
                        continue

class SysTssCommand(gdb.Command):
    "Dump TSS"

    def __init__ (self):
        super (SysTssCommand, self).__init__ ("sys tss",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def invoke (self, arg, from_tty):
        args = arg.split(" ")
        ad = long(args[0], 0)
        inf = gdb.selected_inferior()
        sd = tss_data(sex='<', wsize=32).unpack(inf.read_memory(ad, 102))
        print sd

class SegmentDecodeCommand(gdb.Command):
    "Decode Segment descriptor"

    def __init__ (self):
        super (SegmentDecodeCommand, self).__init__ ("sys sec_desc",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def invoke (self, arg, from_tty):
        sd = segment_desc(int(arg, 0))
        print sd

class SysMemMap(gdb.Command):
    "Print Memory Map from Page Directory"

    def __init__ (self):
        super (SysMemMap, self).__init__ ("sys memmap",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def parse_pdt(self, mmap, ad, start, end):
        # Read whole PD for performance
        pd =struct.unpack("1024I",self.inf.read_memory(ad, 1024*4))
        for i in range(start, end):
            if i%20 == 0:
              print "%d/1023" % i
            pde = pd[i]
            if pde&1:
                # check for 4MB page
                if pde&(1<<7):
                    page_base = ((pde>>12)&0xFF)<<32
                    page_base |= pde&0xFFC00000
                    print "%08x : present : %08x (4MB)" % ((i<<22), p_b)
                    mmap.add_page_present(i<<22, 4*1024*1024, page_base)
                else:
                    # PT base
                    pt_b = pde&0xFFFFF000
                    s = "%08x PS:%d US:%d" % (pt_b, (pde>>7)&1, (pde>>2)&1)
                    # Read whole PT for performance
                    pt =struct.unpack("1024I",self.inf.read_memory(pt_b, 1024*4))
                    for j in range(0, 1024):
                        pte = pt[i]
                        p_b = pte&0xFFFFF000
                        if pte&1:
                            #print "%08x : present : %08x" % (((i<<22)|(j<<12)), p_b)
                            mmap.add_page_present((i<<22)|(j<<12), 4096, p_b)
                        else:
                            #print "%08x : NOT present" % ((i<<22)|(j<<12))
                            mmap.add_page_4k_not_present((i<<22)|(j<<12))

    def parse_pml4(self, mmap, ad, start, end):
        for i in range(start, end):
            #if i%20 == 0:
            #  print "%d/512" % i
            pml4te = struct.unpack("Q", self.inf.read_memory(ad+i*8, 8))[0]
            if pml4te&1:
                pdp_b = pml4te&0x1FFFFFF000
                s = "PML4TE : (%016x) %016x PS:%d US:%d" % (i<<39, pdp_b, (pml4te>>7)&1, (pml4te>>2)&1)
                print s
                for j in range(0,512):
                    pdpe = struct.unpack("Q", self.inf.read_memory(pdp_b+j*8, 8))[0]
                    if pdpe&1:
                        pd_b = pdpe&0x1FFFFFFF000
                        s = "  PDPE   : (%016x) %016x PS:%d US:%d" % ((i<<39)|j<<30, pd_b, (pdpe>>7)&1, (pdpe>>2)&1)
                        print s
                        for k in range(0, 512):
                            pde = struct.unpack("Q", self.inf.read_memory(pd_b+k*8, 8))[0]
                            if pde&1:
                                pt_b = pde&0x1FFFFFFF000
                                s = "    PDE    : (%016x) %016x PS:%d US:%d" % ((i<<39)|(j<<30)|(k<<21), pt_b, (pde>>7)&1, (pde>>2)&1)
                                #print s
                                if (pde>>7)&1 == 1: # 2Mb page
                                   mmap.add_page_present((i<<39)|(j<<30)|(k<<21), 2*1024*1024)
                                   continue 

                                for l in range(0, 512):
                                    pte = struct.unpack("Q", self.inf.read_memory(pt_b+l*8, 8))[0]
                                    p_b = pte&0x1FFFFFFF000
                                    if pte&1:
                                        s = "      PTE    : (%016x) %016x PS:%d US:%d" % ((i<<39)|(j<<30)|(k<<21)|(l<<12), p_b, (pte>>7)&1, (pte>>2)&1)
                                        #print s
                                        mmap.add_page_present((i<<39)|(j<<30)|(k<<21)|(l<<12), 4096)
                                    #else:
                                    #    mmap.add_page_4k_not_present((i<<39)|(j<<30)|(k<<21)|(l<<12))


    def invoke (self, arg, from_tty):
        args = arg.split(" ")
        ad = long(args[0], 0) # base address of tables (cr3)
        
        self.inf = gdb.selected_inferior()

        print args
        if len(args) >= 3:
            start = long(args[1], 0) # first entry index
            end = long(args[2], 0) # last entry index
        else:
            start = 0
            end = 1024

        mmap = mem_map()
        # long mode ?
        # TODO : use gdb.architecture
        if len(args) == 4 and args[3] == "-l":
            self.parse_pml4(mmap, ad, start, end)
        else :
            self.parse_pdt(mmap, ad, start, end)
        mmap.prt()


SysCommand()
SegmentDecodeCommand()
GdtDumpCommand()
SysTssCommand()
SysMemMap()
