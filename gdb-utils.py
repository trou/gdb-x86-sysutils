import gdb
import struct

class segment_desc:
    def __init__(self, val):
        self.desc = val

        self.base = (self.desc >> 16)&0xFFFFF
        self.base |= ((self.desc >> (32+24))&0xFFF)<<24;

        self.limit = self.desc & 0xFFFF;
        self.limit |= (self.desc >> (32+16))&0xF;

        self.type = (self.desc >> (32+8))&0xF;

        self.s = (self.desc >> (32+12))&1;
        self.dpl = (self.desc >> (32+13))&3;
        self.p = (self.desc >> (32+15))&1;
        self.avl = (self.desc >> (32+20))&1;
        self.l = (self.desc >> (32+21))&1;
        self.db = (self.desc >> (32+22))&1;
        self.g = (self.desc >> (32+23))&1;

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
        if self.s == 1:
            # CODE/DATA
            s = "DPL : %d Base : %08x Limit : %04x " % (self.dpl, self.base, self.limit)
            s += "D/B: %db " % (16,32)[self.db]
            s += "Type: %s" % ",".join(self.type_str())
        else:
            # System
            s = "DPL : %d Base : %08x Limit : %04x " % (self.dpl, self.base, self.limit)
            s += "AVL : %d  " % self.avl
            s += "Type: %s" % ("Reserved", "16b TSS (A)", "LDT", "16b TSS (B)", "16b Call G", "Task Gate", "16b Int G", "16b Trap G", "Reserved", "32b TSS (A)", "Reserved", "32b TSS (B)", "32b Call G", "Reserved", "32b Int G", "32b Trap G")[self.type]
        return s

class GdtCommand(gdb.Command):
    "GDT command for GDT parsing"

    def __init__ (self):
        super (GdtCommand, self).__init__ ("gdt",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

class GdtDumpCommand(gdb.Command):
    "Dump GDT to console"

    def __init__ (self):
        super (GdtDumpCommand, self).__init__ ("gdt dump",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def invoke (self, arg, from_tty):
        ad = long(arg, 0)
        inf = gdb.selected_inferior()
        for i in range(0, 4096):
            desc = struct.unpack("<Q", inf.read_memory(ad+i*8, 8))[0]
            if desc != 0:
                print "#%04d : %016x : %s" % (i,desc, segment_desc(desc))

class GdtDecodeCommand(gdb.Command):
    "Decode GDT descriptor"

    def __init__ (self):
        super (GdtDecodeCommand, self).__init__ ("gdt desc",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

    def invoke (self, arg, from_tty):
        sd = segment_desc(int(arg, 0))
        print sd

GdtCommand()
GdtDecodeCommand()
GdtDumpCommand()
