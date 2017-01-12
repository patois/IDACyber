from PyQt5.QtGui import QColor
from idacyber import ColorFilter
from ida_kernwin import asklong

class Xor(ColorFilter):
    name = "8-Bit XOR"

    def __init__(self):
        self.key = 0x80

    def _set_xor_key(self):
        key = asklong(self.key, "Please enter 8-Bit XOR key")
        if key is not None:
            self.key = key & 0xFF

    def on_activate(self, idx):
        self._set_xor_key()
        
    def on_right_click(self, addr):
        self._set_xor_key()

    def do_filter(self, buf, addr):
        colors = []
        for c in buf:
            c = (ord(c) ^ self.key) & 0xFF
            colors.append(QColor(0, c, c))
        return colors


    def get_tooltip(self, addr):
        return "Current key is 0x%02X" % self.key

def FILTER_ENTRY():
    return Xor()
