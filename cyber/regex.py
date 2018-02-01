from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_byte
from ida_kernwin import ask_str, warning
import re

class Regex(ColorFilter):
    name = 'Regex'
    help = 'Highlight regular expression.\n\nRMB sets expression.'

    def __init__(self):
        self.pattern = ''
        self.regex = None
        return

    def _set_regex(self):
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
        return

    def on_mb_click(self, event, addr, size, mouse_offs):
        if event.button() == Qt.RightButton:
            self._set_regex()
        return

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []

        for mapped, buf in buffers:
            offs = 0
            matches = []
            if mapped:        
                if self.regex is not None:
                    for m in re.finditer(self.regex, buf):
                        matches += range(m.start(), m.end())

                for c in buf:
                    r = g = b = ord(c) & 0x3F
                    if offs in matches:
                        r, g, b = (r+(0xFF-0x3F)&0xFF, g, b)
                    colors.append((True, qRgb(r, g, b)))
                    offs += 1
            else:
                for i in xrange(len(buf)):
                    colors.append((False, None))
        return colors
    
    def on_get_tooltip(self, addr, size, mouse_offs):
        return "0x%02X" % get_byte(addr + mouse_offs)

def FILTER_INIT(pw):
    return Regex()
    
def FILTER_EXIT():
    return