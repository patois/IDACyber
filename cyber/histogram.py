from math import log
from idacyber import ColorFilter
import ida_kernwin

# http://www.color-hex.com/color-palette/54234

# taken from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
def H(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*log(p_x, 2)
    return entropy

class Histogram(ColorFilter):
    name = "Histogram"
    width = 256
    lock_width = True
    zoom = 2
    link_pixel = False
    support_selection = True
    highlight_cursor = False
    disable_data = True

    def __init__(self):
        self.entropy = 0.0
        self.max_count = 0
        self.hist = []
        self.bufsize = 0

    def on_get_annotations(self, address, size, mouse_offs):
        cursor_x = mouse_offs % Histogram.width
        annotations = None
        if self.bufsize and cursor_x in xrange(len(self.hist)):
            count = self.hist[cursor_x]
            annotations = [(None, None, 'Start: 0x%X' % address, 0xf2f0f0),
            (None, None, 'End: 0x%X' % (address+self.bufsize), 0xf2f0f0),
            (None, None, 'Size: 0x%X' % (self.bufsize), 0xf2f0f0),
            (None, None, '', None),
            (None, None, 'Entropy: %f' % float(self.entropy), 0xf2f0f0),
            (None, None, 'Byte: 0x%02X x %d (%.2f%%)' % (cursor_x, count, (count/float(self.bufsize))*100.0), 0xf2f0f0)]
        return annotations

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = [(True, 0x193d5a)] * size
        self.hist = [0] * 256
        width = Histogram.width

        height = int(round(size / width))
        e = ''
        self.bufsize = 0
        for mapped, buf in buffers:
            if mapped:
                self.bufsize += len(buf)
                for c in buf:
                    e += c
                    self.hist[ord(c)] += 1
        self.entropy = H(e)
        self.max_count = max(self.hist)
        cursor_x = mouse_offs % width

        if self.max_count and height:
            bars = []
            for i in xrange(len(self.hist)):
                count = self.hist[i]
                bars.append(int(round((count/float(self.max_count))*height)))

            for i in xrange(len(bars)):
                dst_y = bars[i]
                for y in xrange(dst_y):
                    colors[height*width - width+i - y*width] = (True, 0xf2f0f0 if i == cursor_x else [0xffad00,0xc10000][i%2])

        return colors

    def on_get_tooltip(self, addr, size, mouse_offs):
        i = mouse_offs % Histogram.width
        tooltip = 'This space for rent'
        if self.bufsize:
            tooltip = '0x%02X x %d  (%.2f%%)' % (i, self.hist[i], (self.hist[i]/float(self.bufsize))*100.0)

        return tooltip

def FILTER_INIT(pw):
    return Histogram()
    
def FILTER_EXIT():
    return