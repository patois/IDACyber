from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_bytes import get_item_size

class GameBoy(ColorFilter):
    name = "GameBoy"

    def do_filter(self, buf, addr):
        #Bit    7  6  5  4  3  2  1  0
        #Data   R  R  R  G  G  G  B  B
        colors = []
        for c in buf:           
            c = ord(c)
            red = c & 0xE0
            green = (c << 3) & 0xE0
            blue = (c << 6) & 0xC0
            gray = red * 0.3 + green * 0.59 + blue * 0.11
            colors.append(QColor(gray, gray, gray))
        return colors

    def get_tooltip(self, addr):
        return "%X: item size %d" % (addr, get_item_size(addr))
    
def FILTER_ENTRY():
    return GameBoy()
