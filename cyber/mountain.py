from __future__ import print_function
from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_bytes import get_byte
from ida_funcs import get_func
from ida_bytes import get_flags, is_strlit, get_item_head

try:
    xrange          # Python 2
except NameError:
    xrange = range  # Python 3


class Mountain(ColorFilter):
    name = "Mountain"
    highlight_cursor = True
    help = 'Emphasizes functions and strings'

    def on_activate(self, idx):
        print(Mountain.help)

    def on_mb_click(self, button, addr, mouse_offs):
        print('click at %X' % (addr + mouse_offs))

    def _is_string(self, ea):
        head = get_item_head(ea)
        flags = get_flags(head)
        return is_strlit(flags)


    def render_img(self, buf, addr, mouse_offs):
        colors = []
        for offs in xrange(len(buf)):
            r = g = b = 0
            c = ord(buf[offs]) & 0xFF
            ea = addr + offs
            f = get_func(ea)
            if f:
                g = b = c
            elif self._is_string(ea):
                g = c
            else:
                r = g = b = c
            colors.append(qRgb(r, g, b))
        return colors

    def get_tooltip(self, addr, mouse_offs):
        return "0x%02X" % get_byte(addr + mouse_offs)

def FILTER_ENTRY():
    return Mountain()
