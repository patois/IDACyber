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
            tmp = b''
            for mapped, buf in buffers:
                tmp += buf if mapped else b''
            self.size = len(tmp)            
            c = Counter(tmp.replace(b"\x00",b""))
            mc = c.most_common(1)
            if len(mc):
                cur, self.occurence = mc[0]
                if cur != self.key:
                    msg('Key %02Xh - %d/%d (%.2f%%)\n' % (cur, self.occurence, self.size, float(self.occurence)/float(self.size)*100.0))
                    self.key = cur

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        self._update_key(buffers)
        for mapped, buf in buffers:
            if mapped:
                for c in buf:
                    c = (c ^ self.key) & 0xFF
                    colors.append((True, qRgb(c, 0, c)))
            else:
                for i in range(len(buf)):
                    colors.append((False, None))
        return colors


    def on_get_tooltip(self, addr, size, mouse_offs):
        result = None
        if self.size:
            result = "Key %02Xh - %d/%d (%.2f%%)" % (self.key, self.occurence, self.size, float(self.occurence)/float(self.size)*100.0)
        return result

def FILTER_INIT(pw):
    return AutoXor()
    
def FILTER_EXIT():
    return