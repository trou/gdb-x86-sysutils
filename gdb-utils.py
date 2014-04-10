import gdb

class segment_desc:
    def __init__(self, val):
        print hex(val)
        self.desc = val

        self.base = (self.desc >> 16)&0xFFFFF
        self.base |= ((self.desc >> (32+24))&0xFFF)<<24;

        self.limit = self.desc & 0xFFFF;
        self.limit |= (self.desc >> (32+16))&0xF;

        self.type = (self.desc >> (32+8))&3;

    def __str__(self):
        return "Base : %08x Limit : %05x Type: %d" % (self.base, self.limit, self.type)

class GdtCommand(gdb.Command):
    "GDT command for GDT parsing"

    def __init__ (self):
        super (GdtCommand, self).__init__ ("gdt",
            gdb.COMMAND_SUPPORT,
            gdb.COMPLETE_NONE, True)

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
