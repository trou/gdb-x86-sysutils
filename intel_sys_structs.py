#  Copyright 2015 - Raphaël Rigo
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
import cstruct

class mem_map:
    """
    Stores virt->phy map
    Structure is a dict of :
        addr => (start, end, physical address of start, physical end)
    each referenced page should be added like this :
        start => (start, end)
        end => (start, end)
    Adjacent pages are merged in add_page if physical 
    addresses are adjacent too
    """
    def __init__(self):
        self.p = {}
        self.np = {}

    def add_page(self, m, new_page_addr, size, new_page_phy=None):
        new_page_end = new_page_addr+size
        if not new_page_phy:
            new_page_phy = new_page_addr
        new_phy_end = new_page_phy+size

        # Default case
        new_r = (new_page_addr, new_page_end, new_page_phy, new_phy_end)

        # Check if adjacent :
        if new_page_addr in m:
            # print "Found start in m " +repr(m[new_page_addr])
            # addr equals previous page end
            # => coallesce with previous
            if new_page_addr == m[new_page_addr][1]:
                # check if physical is also adjacent with previous end
                if new_page_phy == m[new_page_addr][3] :
                    new_r = (m[new_page_addr][0], new_page_end, m[new_page_addr][2], new_phy_end)
                    del m[new_page_addr] # delete old "end"
            else:
                raise Exception("Page already present !")
        elif new_page_end in m:
            # print "Found end in m :"+repr(m[new_page_end])
            # End of new page is equal to present page addr
            # merge with next
            # check if physical is also adjacent :
            if new_page_end == m[new_page_end][2]:
                new_r = (new_page_addr, m[new_page_end][1], new_page_phy, m[new_page_end][3])
                del m[new_page_end] # delete start of old page

        # Add new entry
        m[new_r[0]] = new_r
        m[new_r[1]] = new_r

    def add_page_present(self, addr, size, phy=None):
        self.add_page(self.p, addr, size, phy)

    def add_page_4k_not_present(self, addr):
        self.add_page(self.np, addr, 4096)

    def prt(self):
        s = set(self.p.values())
        
        for r in sorted(list(s), key = lambda m: m[0]):
            print("%08x-%08x => (%08x-%08x)" % r)

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

class tss_data(cstruct.CStruct):
    _fields = [ ("ptl", "u16"),
                ("_","u16"),
                ("esp0","u32"),
                ("ss0","u16"),
                ("_","u16"),
                ("esp1","u32"),
                ("ss1","u16"),
                ("_","u16"),
                ("esp2","u32"),
                ("ss2","u16"),
                ("_","u16"),
                ("cr3","u32"),
                ("eip","u32"),
                ("eflags","u32"),
                ("eax","u32"),
                ("ecx","u32"),
                ("edx","u32"),
                ("ebx","u32"),
                ("esp","u32"),
                ("ebp","u32"),
                ("esi","u32"),
                ("edi","u32"),
                ("es","u16"),
                ("_","u16"),
                ("cs","u16"),
                ("_","u16"),
                ("ss","u16"),
                ("_","u16"),
                ("ds","u16"),
                ("_","u16"),
                ("fs","u16"),
                ("_","u16"),
                ("gs","u16"),
                ("_","u16"),
                ("ldtss","u16"),
                ("t","u16"),
                ("iomap","u16")]
    def __str__(self):
        s = "Prev : %04x  CR3 : %08x, CS:EIP: %04x:%08x " % (self.ptl, self.cr3, self.cs, self.eip)
        s += "ds : %04x " % (self.ds)
        s += "es : %04x " % (self.es)
        s += "fs : %04x " % (self.fs)
        s += "gs : %04x " % (self.gs)
        s += "ss : %04x " % (self.ss)
        return s
