from PyQt5.QtGui import qRgb
from idacyber import ColorFilter
from ida_kernwin import msg
from collections import Counter

class AutoXor(ColorFilter):
    name = "AutoXOR"

    def __init__(self):
        self.key = 0x80
        self.occurence = 0
        self.size = 0

    def _update_key(self, buffers):
        if buffers:
            tmp = ''
            for mapped, buf in buffers:
                tmp += buf if mapped else ''
            self.size = len(tmp)            
            c = Counter(tmp.replace("\x00",""))
            mc = c.most_common(1)
            if len(mc):
                cur, self.occurence = mc[0]
                cur = ord(cur)
                if cur != self.key:
                    msg('Key %02Xh - %d/%d (%.2f%%)\n' % (cur, self.occurence, self.size, float(self.occurence)/float(self.size)*100.0))
                    self.key = cur

    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        self._update_key(buffers)
        for mapped, buf in buffers:
            if mapped:
                for c in buf:
                    c = (ord(c) ^ self.key) & 0xFF
                    colors.append((True, qRgb(c, 0, c)))
            else:
                for i in xrange(len(buf)):
                    colors.append((False,0))
        return colors


    def get_tooltip(self, addr, mouse_offs):
        result = None
        if self.size:
            result = "Key %02Xh - %d/%d (%.2f%%)" % (self.key, self.occurence, self.size, float(self.occurence)/float(self.size)*100.0)
        return result

def FILTER_ENTRY():
    return AutoXor()
