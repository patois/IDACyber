from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_bytes import get_byte

class Heatmap(ColorFilter):
    name = "Heatmap"

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        for mapped, buf in buffers:
            if mapped:                
                for c in buf:
                    r, g, b = self.hm(c)
                    colors.append((True, qRgb(r, g, b)))
            else:
                for i in range(len(buf)):
                    colors.append((False, None))
        return colors

    def on_get_tooltip(self, addr, size, mouse_offs):
        return "0x%02X" % get_byte(addr + mouse_offs)

    # code taken from
    # http://stackoverflow.com/questions/20792445/calculate-rgb-value-for-a-range-of-values-to-create-heat-map
    def hm(self, value):
        ratio = 2 * (value) / (255)
        b = int(max(0, 255*(1 - ratio)))
        r = int(max(0, 255*(ratio - 1)))
        g = 255 - b - r
        return r, g, b

def FILTER_INIT(pw):
    return Heatmap()
    
def FILTER_EXIT():
    return