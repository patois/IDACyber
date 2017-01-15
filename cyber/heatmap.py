from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_bytes import get_byte

class Heatmap(ColorFilter):
    name = "Heatmap"

    def do_filter(self, buf, addr):
        colors = []
        for c in buf:
            c = ord(c) & 0xFF
            r, g, b = self.hm(c)
            colors.append(QColor(r, g, b))
        return colors

    def get_tooltip(self, addr):
        return "0x%02X" % get_byte(addr)

    # code taken from
    # http://stackoverflow.com/questions/20792445/calculate-rgb-value-for-a-range-of-values-to-create-heat-map
    def hm(self, value):
        ratio = 2 * (value) / (255)
        b = int(max(0, 255*(1 - ratio)))
        r = int(max(0, 255*(ratio - 1)))
        g = 255 - b - r
        return r, g, b

    
def FILTER_ENTRY():
    return Heatmap()
