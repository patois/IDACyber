from PyQt5.QtGui import qRgb
from idacyber import ColorFilter

class NES(ColorFilter):
    name = "NES"
    help = "8-Bit colors"

    def render_img(self, buffers, addr, mouse_offs):
        #Bit    7  6  5  4  3  2  1  0
        #Data   R  R  R  G  G  G  B  B
        colors = []
        for mapped, buf in buffers:
            if mapped:
                for c in buf:
                    c = ord(c)
                    red = c & 0xE0
                    green = (c << 3) & 0xE0
                    blue = (c << 6) & 0xC0
                    colors.append((True, qRgb(red, green, blue)))
            else:
                for i in xrange(len(buf)):
                    colors.append((False,0))
        return colors
    
def FILTER_ENTRY():
    return NES()
