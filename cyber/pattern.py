from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import ask_long
from ida_bytes import get_byte
from ida_kernwin import ask_str, warning
import re

class Pattern(ColorFilter):
    name = 'Pattern'
    help = 'Highlight regex pattern.\n\nRMB sets regex.'

    def __init__(self):
        self.pattern = ''
        self.regex = None

    def _set_pattern(self):
        while True:
            pat = ask_str(self.pattern, 0, "Regular expression:")
            if pat is None:
                break
            
            try:
                c = 0
                prog = re.compile(pat)
                self.pattern = pat
                self.regex = prog
                break
            except:
                warning("Invalid expression!")
                continue

    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.RightButton:
            self._set_pattern()

    def render_img(self, buf, addr, mouse_offs):
        colors = []
        matches = []

        if self.regex is not None:
            for m in re.finditer(self.regex, buf):
                matches += range(m.start(), m.end())

        colors = []
        offs = 0
        for c in buf:
            r = g = b = ord(c) & 0x3F
            if offs in matches:
                r, g, b = (r+(0xFF-0x3F)&0xFF, g, b)
            colors.append(qRgb(r, g, b))
            offs += 1

        return colors
    
    def get_tooltip(self, addr, mouse_offs):
        return "0x%02X" % get_byte(addr + mouse_offs)

def FILTER_ENTRY():
    return Pattern()
