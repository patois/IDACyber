from PyQt5.QtGui import qRgb
from idacyber import ColorFilter

class NES(ColorFilter):
    name = "NES"
    help = "Simple 8-Bit color filter"

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        #Bit    7  6  5  4  3  2  1  0
        #Data   R  R  R  G  G  G  B  B
        colors = []
        for mapped, buf in buffers:
            if mapped:
                for c in buf:
                    red = c & 0xE0
                    green = (c << 3) & 0xE0
                    blue = (c << 6) & 0xC0
                    colors.append((True, qRgb(red, green, blue)))
            else:
                for i in range(len(buf)):
                    colors.append((False, None))
        return colors
    
def FILTER_INIT(pw):
    return NES()
    
def FILTER_EXIT():
    return