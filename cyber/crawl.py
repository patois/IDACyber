from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_end, get_item_head
import ida_idaapi
from ida_kernwin import msg
from ida_funcs import get_func, get_func_name
from ida_name import get_name

class Crawl(ColorFilter):
    name = "Crawl"
    highlight_cursor = False
    help = 'Highlight functions and items - RMB toggles mode'

    def __init__(self):
        self.hl_color = 100
        self.switch = 1
        self.mode = ["Item length", "Functions"]

    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.MiddleButton:
            pass
        elif button == Qt.RightButton:
            self.switch ^= 1
            msg('Highlighting %s\n' % self.mode[self.switch])

    def get_tooltip(self, addr, mouse_offs):
        tooltip = '%X: ' % (addr + mouse_offs)

        if self.switch == 0:
            tooltip += '%s' % get_name(get_item_head(addr + mouse_offs))
        else:
            f = get_func(addr + mouse_offs)
            if f:
                tooltip += '%s' % get_func_name(f.startEA)
        return tooltip

    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        head = ida_idaapi.BADADDR
        tail = ida_idaapi.BADADDR
        goffs = 0

        for mapped, buf in buffers:
            if mapped:
                if mouse_offs is not None:
                    if self.switch == 0: # data
                        head = get_item_head(addr + mouse_offs)
                        tail = get_item_end(addr + mouse_offs)
                    else: # code
                        f = get_func(addr + mouse_offs)
                        if f:
                            head = f.startEA
                            tail = f.endEA

                for pos in xrange(len(buf)):
                    c = ord(buf[pos]) & 0xFF
                    
                    highlight = False
                    if mouse_offs is not None:

                        if addr + pos + goffs >= head and addr + pos + goffs < tail:
                            highlight = True
                    if highlight:
                        colors.append((True, qRgb(c, 0xFF, self.hl_color)))
                    else:
                        colors.append((True, qRgb(c, 0, 0)))
            else:
                for pos in xrange(len(buf)):
                    colors.append((False, 0))
            goffs += len(buf)
        return colors

def FILTER_ENTRY():
    return Crawl()
