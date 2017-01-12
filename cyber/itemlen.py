from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_item_head
from copy import copy

class ItemLength(ColorFilter):
    name = "Item length"

    def do_filter(self, buf, addr):
        colors = []
        start = addr
        end = start + len(buf)
        ea = start
        col1 = QColor(0xFF, 0x00, 0x00)
        col2 = QColor(0x00, 0x00, 0x00)
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
