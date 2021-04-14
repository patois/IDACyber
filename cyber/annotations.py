from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_byte, get_item_head, get_item_end
from ida_name import get_name
from ida_lines import generate_disasm_line, GENDSM_FORCE_CODE, GENDSM_REMOVE_TAGS

class Annotations(ColorFilter):
    name = "Annotations"
    help =  "This filter shows how to add annotations to a graph."

    def __init__(self):
        # "space-gray like Color Palette" http://www.color-hex.com/color-palette/2280
        self.colormap = [0x343d46, 0x4f5b66, 0x65737e, 0xa7adba, 0xc0c5ce]
        self.red = [0xCC3700, 0xFF4500]

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        goffs = 0

        if mouse_offs is not None:
            head = get_item_head(addr + mouse_offs)
            tail = get_item_end(addr + mouse_offs)

        for mapped, buf in buffers:
            if mapped:        
                for i in range(len(buf)):           
                    c = buf[i]
                    if addr + i + goffs >= head and addr + i + goffs < tail:
                        col = self.red[1]
                    else:
                        col = self.colormap[int(c/(0xff/(len(self.colormap)-1)))]

                    colors.append((True, col))
            else:
                for i in range(len(buf)):
                    if addr + i + goffs >= head and addr + i + goffs < tail:
                        colors.append((False, self.red[0]))
                    else:
                        colors.append((False, None))

            goffs += len(buf)

        return colors

    def on_get_annotations(self, address, size, mouse_offs):
        item_ea = get_item_head(address + mouse_offs)
        cursor_ea = address + mouse_offs
        name = get_name(item_ea)
        if len(name):
            name = "(%s)" % name
        else:
            name = ""
        ann = [(item_ea, self.red[0], "Item: %X" % (item_ea), self.colormap[-1]),
        (None, None, "  Size: %d %s" % (get_item_size(get_item_head(cursor_ea)), name), self.colormap[-3]),
        (cursor_ea, self.colormap[-1], "Cursor: %X" % (cursor_ea), self.colormap[-1]),
        (None, None, "  %s" % generate_disasm_line(cursor_ea, GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS), self.colormap[-3]),
        (None, None, "  Value: %02X" % get_byte(cursor_ea), self.colormap[-3]),
        ]
        return ann

def FILTER_INIT(pw):
    return Annotations()
    
def FILTER_EXIT():
    return