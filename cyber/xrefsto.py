from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_xref import xrefblk_t

class xrefsto(ColorFilter):
    name = "xrefs to"

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
        xrefs = []
        for i in xrange(len(buf)):
            xrefs.append(self.xrefcount(addr+i))

        if xrefs:
            minimum, maximum = min(xrefs), max(xrefs)
            
        for count in xrefs:
            r, g, b = self.hm(minimum, maximum, count)
            colors.append(QColor(r, g, b))
        return colors

    def hm(self, minimum, maximum, value):
        if minimum == maximum:
            maximum = 1
        minimum, maximum = float(minimum), float(maximum)
        ratio = 2 * (value-minimum) / (maximum - minimum)
        b = int(max(0, 255*(1 - ratio)))
        r = int(max(0, 255*(ratio - 1)))
        g = 255 - b - r
        return r, g, b

    def get_tooltip(self, addr):
        return "%d xrefs" % self.xrefcount(addr)
    
def FILTER_ENTRY():
    return xrefsto()
