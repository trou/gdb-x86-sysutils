import gdb
import struct

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
                   self.gs, _, ldtss, _, t, iomap) = struct.unpack("HHIHHIHHIHH11I16H", data)

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
        print args
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
                            print tss 
                    except:
                        continue

class GdtTssCommand(gdb.Command):
    "Dump TSS"

    def __init__ (self):
        super (GdtTssCommand, self).__init__ ("sys tss",
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
        super (GdtDecodeCommand, self).__init__ ("sys sec_desc",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def invoke (self, arg, from_tty):
        sd = segment_desc(int(arg, 0))
        print sd


SysCommand()
SegmentDecodeCommand()
GdtDumpCommand()
GdtTssCommand()
