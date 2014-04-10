import gdb
import struct

class segment_desc:
    def __init__(self, val):
        self.desc = val

        self.base = (self.desc >> 16)&0xFFFFF
        self.base |= ((self.desc >> (32+24))&0xFFF)<<24;

        self.limit = self.desc & 0xFFFF;
        self.limit |= (self.desc >> (32+16))&0xF;

        self.type = (self.desc >> (32+8))&3;

        self.s = (self.desc >> (32+12))&1;
        self.dpl = (self.desc >> (32+13))&3;
        self.p = (self.desc >> (32+15))&1;
        self.avl = (self.desc >> (32+20))&1;
        self.l = (self.desc >> (32+21))&1;
        self.db = (self.desc >> (32+22))&1;
        self.g = (self.desc >> (32+23))&1;

    def __str__(self):
        return "DPL : %d Base : %08x Limit : %05x Type: %d" % (self.dpl, self.base, self.limit, self.type)

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
        for i in range(0, 4095):
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
