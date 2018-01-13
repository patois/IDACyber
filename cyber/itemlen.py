from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_item_head
from copy import copy

try:
    xrange          # Python 2
except NameError:
    xrange = range  # Python 3


class ItemLength(ColorFilter):
    name = "Item length"
    highlight_cursor = True
    help = None

    def render_img(self, buf, addr, mouse_offs):
        colors = []
        start = addr
        end = start + len(buf)
        ea = start
        col1 = qRgb(0xDC, 0xDC, 0xDC)
        col2 = qRgb(0x00, 0x00, 0x00)
        cols = [col1, col2]

        pos = 0
        head = get_item_head(start)
        sz = get_item_size(start)
        if head < start:
            sz -= (start - head)
        while ea < end:
            for i in xrange(sz):
                colors.append(copy(cols[pos]))

            pos = (pos + 1) % len(cols)
            if ea + sz > end:
                sz = ea + sz - end
            ea += sz
            sz = get_item_size(ea)
        return colors

def FILTER_ENTRY():
    return ItemLength()
