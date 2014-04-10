import gdb
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
	print arg

GdtCommand()
GdtDecodeCommand()
