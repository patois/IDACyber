from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_byte, get_item_head, get_item_end
from ida_name import get_name

class Annotations(ColorFilter):
    name = "Annotations"
    help =  "Annotations example"

    def __init__(self):
        # "space-gray like Color Palette" http://www.color-hex.com/color-palette/2280
        self.colormap = [0x343d46, 0x4f5b66, 0x65737e, 0xa7adba, 0xc0c5ce]

    def render_img(self, buffers, addr, mouse_offs):
        #Bit    7  6  5  4  3  2  1  0
        #Data   R  R  R  G  G  G  B  B
        colors = []
        goffs = 0

        if mouse_offs is not None:
            head = get_item_head(addr + mouse_offs)
            tail = get_item_end(addr + mouse_offs)

        for mapped, buf in buffers:
            if mapped:        
                for i in xrange(len(buf)):           
                    c = ord(buf[i])
                    if addr + i + goffs >= head and addr + i + goffs < tail:
                        col = qRgb(0xFF, 0x45, 0)
                    else:
                        col = self.colormap[c/(0xff/(len(self.colormap)-1))]

                    colors.append((True, col))
            else:
                for i in xrange(len(buf)):
                    if addr + i + goffs >= head and addr + i + goffs < tail:
                        colors.append((False, qRgb(0xFF, 0x45, 0)))
                    else:
                        colors.append((False, None))

            goffs += len(buf)

        return colors

    def get_annotations(self, address, size, mouse_offs):
        ann = [(address + mouse_offs, self.colormap[-1], "%X (Cursor)" % (address + mouse_offs), self.colormap[-1]),
        (None, None, "  %02X (byte value)" % get_byte(address + mouse_offs), self.colormap[-1]),
        (None, None, "  %d (item size)" % get_item_size(get_item_head(address + mouse_offs)), self.colormap[-1]),
        (None, None, "  %s" % get_name(get_item_head(address + mouse_offs)), self.colormap[-1])]
        return ann

def FILTER_ENTRY():
    return Annotations()

def FILTER_INIT():
    return True
    
def FILTER_EXIT():
    return