from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_xref import xrefblk_t

class xrefs(ColorFilter):
    name = "xrefs"

    def xrefcount(self, addr):
        count = 0
        xrefs = xrefblk_t()
        if xrefs.first_to(addr, 0):
            count +=1
            while xrefs.next_to():
                count += 1
        return count
        

    def do_filter(self, buf, addr):
        colors = []
        for i in xrange(len(buf)):
            count = self.xrefcount(addr+i)
            c = ((count * 16) & 0xFF)
            colors.append(QColor(c, c, c))
        return colors


    def get_tooltip(self, addr):
        return "%d xrefs" % self.xrefcount(addr)
    
def FILTER_ENTRY():
    return xrefs()
