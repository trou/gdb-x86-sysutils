import gdb
import struct
import cstruct

class mem_map:
    def __init__(self):
        self.p = {}
        self.np = {}

    def add_page(self, m, addr, size):
        # Check if adjacent :
        if addr in m:
            # end, coallesce with previous
            if m[addr][1] == addr:
                new_r = (m[addr][0], addr+size)
                m[new_r[0]] = new_r
                del m[addr]
                m[addr+size] = new_r
        elif (addr+size) in m:
            # start, merge with next
            new_r = (addr,m[addr][1])
            del m[addr[0]]
            m[addr[0]]=new_r
            m[addr[1]]=new_r
        elif addr not in m:
            new_r = (addr, addr+size)
            m[addr] = new_r
            m[addr+size] = new_r
        else:
            # should not happen !
            raise Exception("Page already present!")

    def add_page_present(self, addr, size):
        self.add_page(self.p, addr, size)

    def add_page_4k_not_present(self, addr):
        self.add_page_4k(self.np, addr)

    def prt(self):
        s = set(self.p.values())
        
        for r in sorted(list(s), key = lambda m: m[0]):
            print "%08x-%08x" % r

class segment_desc:
    def __init__(self, val):
        self.desc = val

        self.base = (self.desc >> 16)&0xFFFFFF
        self.base |= ((self.desc >> (32+24))&0xFFF)<<24;

        self.limit = self.desc & 0xFFFF;
        self.limit |= ((self.desc >> 32+16)&0xF)<<16;

        self.type = (self.desc >> (32+8))&0xF;

        self.s = (self.desc >> (32+12))&1;
        self.dpl = (self.desc >> (32+13))&3;
        self.p = (self.desc >> (32+15))&1;
        self.avl = (self.desc >> (32+20))&1;
        self.l = (self.desc >> (32+21))&1;
        self.db = (self.desc >> (32+22))&1;
        self.g = (self.desc >> (32+23))&1;

        self.limit *= 4096 if self.g else 1

    def is_tss(self):
        if self.s == 0 and (self.type == 9 or self.type == 11):
            return True
        else:
            return False

    def type_str(self):
        if (self.type>>3)&1:
            # code
            s = "C" if (self.type>>2)&1 else "c"
            s += "R" if (self.type>>1)&1 else "r"
            s += "A" if self.type&1 else "a"
            return ("CODE", s)
        else:
            # data
            s = "E" if (self.type>>2)&1 else "e"
            s += "W" if (self.type>>1)&1 else "w"
            s += "A" if self.type&1 else "a"
            return ("DATA", s)

    def __str__(self):
        if self.p == 0:
            return "Not Present !"
        if self.s == 1:
            # CODE/DATA
            s = "DPL : %d Base : %08x Limit : %08x " % (self.dpl, self.base, self.limit)
            if self.l == 1 and self.db == 0 :
                s += "D/B: 64b "
            else:
                s += "D/B: %db " % (16,32)[self.db]
            s += "Type: %s" % ",".join(self.type_str())
        else:
            # System
            s = "DPL : %d Base : %08x Limit : %08x " % (self.dpl, self.base, self.limit)
            s += "AVL : %d  " % self.avl
            s += "Type: %s" % ("Reserved", "16b TSS (A)", "LDT", "16b TSS (B)", "16b Call G", "Task Gate", "16b Int G", "16b Trap G", "Reserved", "32b TSS (A)", "Reserved", "32b TSS (B)", "32b Call G", "Reserved", "32b Int G", "32b Trap G")[self.type]
        return s

class tss_data:
    def __init__(self, data):
        if len(data) != 104:
            raise Exception("toto")
        self.raw = data
        (self.ptl, _, self.esp0, self.ss0, _, self.esp1, self.ss1, _,
                   self.esp2, self.ss2, _, self.cr3, self.eip, self.eflags, self.eax, self.ecx,
                   self.edx, self.ebx, self.esp, self.ebp, self.esi, self.edi, self.es, _,
                   self.cs, _, self.ss, _, self.ds, _, self.fs, _,
                   self.gs, _, self.ldtss, _, self.t, self.iomap) = struct.unpack("HHIHHIHHIHH11I16H", data)

    def __str__(self):
        s = "Prev : %04x  CR3 : %08x, CS:EIP: %04x:%08x " % (self.ptl, self.cr3, self.cs, self.eip)
        s += "ds : %04x " % (self.ds)
        s += "es : %04x " % (self.es)
        s += "fs : %04x " % (self.fs)
        s += "gs : %04x " % (self.gs)
        s += "ss : %04x " % (self.ss)
        return s
            

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
                        tss = tss_data(inf.read_memory(s.base, 104))
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
        sd = tss_data(inf.read_memory(ad, 104))
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
        for i in range(start, end):
            if i%20 == 0:
              print "%d/1023" % i
            pde = struct.unpack("I", self.inf.read_memory(ad+i*4, 4))[0]
            if pde&1:
                pte_b = pde&0xFFFFF000
                s = "%08x PS:%d US:%d" % (pte_b, (pde>>7)&1, (pde>>2)&1)
                for j in range(0, 1024):
                    pte = struct.unpack("I", self.inf.read_memory(pte_b+j*4, 4))[0]
                    p_b = pte&0xFFFFF000
                    if pte&1:
                        print "%08x : present : %08x" % (((i<<22)|(j<<12)), p_b)
                        mmap.add_page_4k_present((i<<22)|(j<<12))
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
        ad = long(args[0], 0)
        
        self.inf = gdb.selected_inferior()

        print args
        if len(args) >= 3:
            start = long(args[1], 0)
            end = long(args[2], 0)
        else:
            start = 0
            end = 1024

        mmap = mem_map()
        # long mode ?
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
