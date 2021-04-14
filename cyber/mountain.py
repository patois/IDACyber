from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_kernwin import msg
from ida_bytes import get_byte
from ida_funcs import get_func
from ida_bytes import get_flags, is_strlit, get_item_head

class Mountain(ColorFilter):
    name = 'Mountain'
    help = 'Highlight functions and strings.'

    def _is_string(self, ea):
        head = get_item_head(ea)
        flags = get_flags(head)
        return is_strlit(flags)

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        goffs = 0
        for mapped, buf in buffers:
            if mapped:
                for offs in range(len(buf)):
                    r = g = b = 0
                    c = buf[offs] & 0xFF
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
                colors += [(False, None)]*len(buf)
            goffs += len(buf)
        return colors

    def on_get_tooltip(self, addr, size, mouse_offs):
        return '0x%02X' % get_byte(addr + mouse_offs)
    
def FILTER_INIT(pw):
    return Mountain()
    
def FILTER_EXIT():
    return