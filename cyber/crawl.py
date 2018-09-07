from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_end, get_item_head, get_byte, get_item_size
from ida_idaapi import BADADDR
from ida_kernwin import msg
from ida_funcs import get_func, get_func_name
from ida_name import get_name

class Crawl(ColorFilter):
    name = "Crawl"
    highlight_cursor = False
    help = 'Highlight functions and items.\nRMB toggles mode, LMB displays contextual information.'

    def __init__(self):
        self.hl_color = 100
        self.switch = 0
        self.ann = None
        self.last_sel = None
        self.mode = ["Item length", "Functions"]

    def on_get_annotations(self, addr, size, mouse_offs):
        return self.ann

    def on_mb_click(self, event, addr, size, mouse_offs):
        button = event.button()
        if button == Qt.MiddleButton:
            mouse = addr+mouse_offs
            c = get_byte(mouse)
            head, name, size = self._get_item_info(mouse)
            funcname = self._get_func_name(mouse)
            self.ann = [(mouse, qRgb(c, 0xFF, self.hl_color), "Address: %X" % (mouse), qRgb(c, 0xFF, self.hl_color)),
            (None, None, "  Item: %s" % (name), qRgb(c, 0xFF, self.hl_color)),
            (None, None, "  Head: %X" % (head), qRgb(c, 0xFF, self.hl_color)),
            (None, None, "  Size: %d" % (size), qRgb(c, 0xFF, self.hl_color))
            ]
            if funcname:
                self.ann.append((None, None, "  Function: %s" % (funcname), qRgb(c, 0xFF, self.hl_color)))
            self.last_sel = (head, size)
        elif button == Qt.MiddleButton:
            pass
        elif button == Qt.RightButton:
            self.switch ^= 1
            msg('Highlighting %s\n' % self.mode[self.switch])

    def _get_func_name(self, ea):
        f = get_func(ea)
        if f:
            return get_func_name(f.startEA)
        return None

    def _get_item_info(self, ea):
        head = get_item_head(ea)
        name = get_name(head)
        size = get_item_size(head)
        return (head, name, size)

    def on_get_tooltip(self, addr, size, mouse_offs):
        tooltip = '%X: ' % (addr + mouse_offs)

        if self.switch == 0:
            _, name, size = self._get_item_info(addr+mouse_offs)
            tooltip += '%s (%d)' % (name, size)
        else:
            name = self._get_func_name(addr+mouse_offs)
            if name:
                tooltip += '%s' % name
        return tooltip

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        head = BADADDR
        tail = BADADDR
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
                    if self.last_sel:
                        lhead, lsize = self.last_sel
                        if addr + pos + goffs >= lhead and addr + pos + goffs < lhead+lsize:
                            highlight = True
                    if highlight:
                        colors.append((True, qRgb(c, 0xFF, self.hl_color)))
                    else:
                        colors.append((True, qRgb(c, 0, 0)))
            else:
                for pos in xrange(len(buf)):
                    colors.append((False, None))
            goffs += len(buf)
        return colors

def FILTER_INIT(pw):
    return Crawl()
    
def FILTER_EXIT():
    return