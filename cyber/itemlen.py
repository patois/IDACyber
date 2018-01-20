from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_item_head
from copy import copy

# TODO: fix, this code is messed up

class ItemLength(ColorFilter):
    name = "Item length"

    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        cols = [qRgb(0xDC, 0xDC, 0xDC), qRgb(0x00, 0x00, 0x00)]
        colidx = 0
        goffs = 0

        for mapped, buf in buffers:
            if mapped:
                start = ea = addr + goffs
                end = start + len(buf)

                head = get_item_head(start)
                sz = get_item_size(head)
                if head < start:
                    sz -= (start - head)
                while ea < end:
                    for i in xrange(sz):
                        colors.append((True, copy(cols[colidx])))

                    colidx = ((colidx+1) & sz != 0)
                    if ea + sz > end:
                        sz = ea + sz - end
                    ea += sz
                    sz = get_item_size(ea)
            else:
                for i in xrange(len(buf)):
                    colors.append((False, 0))
            goffs += len(buf)
        return colors

def FILTER_ENTRY():
    return ItemLength()
