from PyQt5.QtGui import qRgb
from idacyber import ColorFilter

class NES(ColorFilter):
    name = "NES"
    highlight_cursor = True
    help = None

    def render_img(self, buf, addr, mouse_offs):
        #Bit    7  6  5  4  3  2  1  0
        #Data   R  R  R  G  G  G  B  B
        colors = []
        for c in buf:           
            c = ord(c)
            red = c & 0xE0
            green = (c << 3) & 0xE0
            blue = (c << 6) & 0xC0
            colors.append(qRgb(red, green, blue))
        return colors
    
def FILTER_ENTRY():
    return NES()
