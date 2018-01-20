from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_xref import xrefblk_t

class xrefsto(ColorFilter):
    name = "xrefs to"
    highlight_cursor = False
    help = "Experimental code which highlights xrefs."

    def xrefcount(self, addr):
        count = 0
        xrefs = xrefblk_t()
        if xrefs.first_to(addr, 0):
            count +=1
            while xrefs.next_to():
                count += 1
        return count
        

    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        goffs = 0
        for mapped, buf in buffers:
            xrefs = []
            if mapped: 
                for i in xrange(len(buf)):
                    xrefs.append(self.xrefcount(addr + goffs + i))

                if xrefs:
                    minimum, maximum = min(xrefs), max(xrefs)
                    
                for count in xrefs:
                    r, g, b = self.hm(minimum, maximum, count)
                    colors.append((True, qRgb(r, g, b)))
            else:
                for i in xrange(len(buf)):
                    colors.append((False, 0))
            goffs += len(buf)
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

    def get_tooltip(self, addr, mouse_offs):
        return "%d xrefs" % self.xrefcount(addr + mouse_offs)
    
def FILTER_ENTRY():
    return xrefsto()
