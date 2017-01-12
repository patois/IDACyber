from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_bytes import get_byte

class Heat(ColorFilter):
    name = "Heat"

    def on_activate(self, idx):
        print "Hello from the heat filter example"

    def on_right_click(self, addr):
        print "right click at %X" % addr

    def do_filter(self, buf, addr):
        colors = []
        for c in buf:
            c = ord(c) & 0xFF
            colors.append(QColor(c, 0, 0))
        return colors

    def get_tooltip(self, addr):
        return "0x%02X" % get_byte(addr)
    
def FILTER_ENTRY():
    return Heat()
