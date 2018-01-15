from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import ask_long
import re
from ida_kernwin import askstr, warning

class Pattern(ColorFilter):
    name = 'Pattern'
    highlight_cursor = True
    help = 'Highlight regex pattern.\n\nRMB sets regex.'

    def __init__(self):
        self.pattern = ''
        self.regex = None

    def _set_pattern(self):
        while True:
            pat = askstr(0, self.pattern, "Please specify pattern")
            if pat is None:
                break
            
            try:
                c = 0
                prog = re.compile(pat)
                self.pattern = pat
                self.regex = prog
                break
            except:
                warning("Invalid pattern!")
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
    
def FILTER_ENTRY():
    return Pattern()
