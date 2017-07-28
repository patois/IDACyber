from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import asklong
from ida_bytes import get_byte

class Xor(ColorFilter):
    name = "XOR"
    highlight_cursor = True
    help = None

    def __init__(self):
        self.key = 23

    def _set_xor_key(self, key=None):
        if key is None:
            key = asklong(self.key, "Please enter 8-Bit XOR key")
        if key:
            self.key = key & 0xFF

    def on_activate(self, idx):
        print "%s filter:\n  * pick key from graph with right mouse button\n  * assign key with middle mouse button." % Xor.name

    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.MiddleButton:
            self._set_xor_key()
        elif button == Qt.RightButton:
            key = get_byte(addr + mouse_offs)
            self._set_xor_key(key)

    def render_img(self, buf, addr, mouse_offs):
        colors = []
        for c in buf:
            c = (ord(c) ^ self.key) & 0xFF
            colors.append(qRgb(0, c, c))
        return colors

    def get_tooltip(self, addr, mouse_offs):
        return "%X:\nCursor 0x%02X\nKey: 0x%02X" % (addr + mouse_offs, get_byte(addr + mouse_offs), self.key)

def FILTER_ENTRY():
    return Xor()
