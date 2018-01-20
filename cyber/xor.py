from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import msg, ask_long
from ida_bytes import get_byte

class Xor(ColorFilter):
    name = "XOR"
    help = "Apply 8-bit XOR operation.\n\nMMB: Set XOR key.\nRMB: Pick XOR key."

    def __init__(self):
        self.key = 23

    def _set_xor_key(self, key=None):
        if key is None:
            key = ask_long(self.key, "Specify 8-Bit XOR key")
        if key:
            self.key = key & 0xFF

    def on_activate(self, idx):
        msg("%s filter:\n  * RMB: pick XOR key from rendered image.\n  * MMB: assign XOR key." % Xor.name)

    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.MiddleButton:
            self._set_xor_key()
        elif button == Qt.RightButton:
            key = get_byte(addr + mouse_offs)
            self._set_xor_key(key)

    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        for mapped, buf in buffers:
            if mapped:  
                for c in buf:
                    c = (ord(c) ^ self.key) & 0xFF
                    colors.append((True, qRgb(0, c, c)))
            else:
                for i in xrange(len(buf)):
                    colors.append((False, 0))
        return colors

    def get_tooltip(self, addr, mouse_offs):
        return "%X:\nCursor 0x%02X\nKey: 0x%02X" % (addr + mouse_offs, get_byte(addr + mouse_offs), self.key)

def FILTER_ENTRY():
    return Xor()
