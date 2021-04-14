from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import msg, register_timer, unregister_timer
from collections import Counter

class AutoXor(ColorFilter):
    name = "AutoXOR"
    help = """Finds most common byte within a selected address range or
within currently displayed graph (0-bytes excluded).
The resulting key is then used to xor the graph's colors.

RMB toggles key highlighting."""
    support_selection = True

    def __init__(self, pw):
        self.key = 0x80
        self.occurence = 0
        self.size = 0
        self.annotations = None
        self.pw = pw
        self.highlight_key = True
        self.timer = None
        self.ms = 600
        self.hl_color_idx = 0

    def on_activate(self, idx):
        self._enable_timer()
        return

    def on_deactivate(self):
        if self.timer:
            unregister_timer(self.timer)
            self.timer = None
        return

    def on_mb_click(self, event, addr, size, mouse_offs):
        if event.button() == Qt.RightButton:
            if self.highlight_key and self.timer:
                unregister_timer(self.timer)
            else:
                self._enable_timer()
            self.highlight_key = not self.highlight_key
            self.pw.on_filter_request_update()
        return

    def on_get_annotations(self, addr, size, mouse_offs):
        return self.annotations

    def _enable_timer(self):
        if self.timer:
            unregister_timer(self.timer)
        self.timer = register_timer(self.ms, self._flip_hl_color)
        return

    def _flip_hl_color(self):
        self.hl_color_idx = (self.hl_color_idx + 1) % 2
        if self.pw:
            self.pw.on_filter_request_update()
        return self.ms

    def _update_key(self, buffers):
        if buffers:
            tmp = b""
            for mapped, buf in buffers:
                tmp += buf if mapped else b""
            self.size = len(tmp)            
            c = Counter(tmp.replace(b"\x00",b""))
            mc = c.most_common(1)
            if len(mc):
                cur, self.occurence = mc[0]
                if True:
                #if cur != self.key:
                    #msg('Key %02Xh - %d/%d (%.2f%%)\n' % (cur, self.occurence, self.size, float(self.occurence)/float(self.size)*100.0))
                    self.annotations = [(None, None, "[Stats]", None),
                    (None, None, " Key:          0x%02x" % (cur), None),
                    (None, None, " Distribution: %d/%d (%.2f%%)\n" % (self.occurence,
                        self.size,
                        float(self.occurence)/float(self.size)*100.0), None)]
                    self.key = cur
        return

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        self._update_key(buffers)
        for mapped, buf in buffers:
            if mapped:
                for c in buf:
                    c = (c ^ self.key)
                    if self.highlight_key and not c:
                        colors.append((True, [qRgb(0x20, c, c), qRgb(0x7a, 0x0e, 0x7a)][self.hl_color_idx]))
                    else:
                        colors.append((True, qRgb(0x20, c, c)))
            else:
                colors += [(False, None)]*len(buf)
        return colors

    def on_get_tooltip(self, addr, size, mouse_offs):
        result = None
        if self.size:
            result = "Key %02Xh - %d/%d (%.2f%%)" % (self.key, self.occurence, self.size, float(self.occurence)/float(self.size)*100.0)
        return result

def FILTER_INIT(pw):
    return AutoXor(pw)
    
def FILTER_EXIT():
    return