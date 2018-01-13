from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import ask_long

try:
    xrange          # Python 2
except NameError:
    xrange = range  # Python 3


class Ascii(ColorFilter):
    name = 'Ascii'
    highlight_cursor = True
    help = 'Highlight ascii strings.\n\nSet threshold using right mouse button.'

    def __init__(self):
        self.threshold = 4

    def _set_threshold(self):
        res = ask_long(self.threshold, "Please specify minimum string length")
        if res is not None:
            self.threshold = res

    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.RightButton:
            self._set_threshold()

    def render_img(self, buf, addr, mouse_offs):
        colors = []
        last_offs = None
        cur_len = 0
        offsets = {}
        for i in xrange(len(buf)):
            c = ord(buf[i])
            r = 0
            printable = c >= 0x20 and c <= 0x7E
            if printable:
                if last_offs is not None:
                    cur_len += 1
                else:
                    last_offs = i
                    cur_len = 1
            else:
                if last_offs is not None and cur_len >= self.threshold:
                    offsets[last_offs] = cur_len
                last_offs = None
                cur_len = 0
            # bg color
            colors.append(qRgb(0x10, 0x10, 0x10))

        for k, v in offsets.iteritems():
            for i in xrange(v):
                    c = ord(buf[k+i])
                    b = c + (0xFF - 0x7E)
                    if c >= 0x41 and c <= 0x5A or \
                    c >= 0x61 and c <= 0x7A or \
                    c >= 0x30 and c <= 0x39:
                        colors[k+i] = qRgb(b, b, 0)
                    else:
                        colors[k+i] = qRgb(b, 0, 0)

        return colors

def FILTER_ENTRY():
    return Ascii()
