from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_kernwin import msg
from ida_bytes import get_byte
from ida_funcs import get_func
from ida_bytes import get_flags, is_strlit, get_item_head

class Mountain(ColorFilter):
    name = 'Mountain'
    help = 'Highlight functions and strings.'

    def on_activate(self, idx):
        msg('%s\n' % Mountain.help)

    def on_mb_click(self, button, addr, mouse_offs):
        msg('click at %X\n' % (addr + mouse_offs))

    def _is_string(self, ea):
        head = get_item_head(ea)
        flags = get_flags(head)
        return is_strlit(flags)


    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        goffs = 0
        for mapped, buf in buffers:
            if mapped:
                for offs in xrange(len(buf)):
                    r = g = b = 0
                    c = ord(buf[offs]) & 0xFF
                    ea = addr + goffs + offs
                    f = get_func(ea)
                    if f:
                        g = b = c
                    elif self._is_string(ea):
                        g = c
                    else:
                        r = g = b = c
                    colors.append((True, qRgb(r, g, b)))
            else:
                for i in xrange(len(buf)):
                    colors.append((False, 0))
            goffs += len(buf)
        return colors

    def get_tooltip(self, addr, mouse_offs):
        return '0x%02X' % get_byte(addr + mouse_offs)
    
def FILTER_ENTRY():
    return Mountain()
