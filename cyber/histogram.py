from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from math import log

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
    show_address_range = False
    support_selection = True

    def __init__(self, pw):
        self.annotations = None
        self.pw = pw
        self.entropy = 0.0
        self.max_count = 0
        self.hist = []

    def on_get_annotations(self, address, size, mouse_offs):
        return self.annotations

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = [(True, 0x193d5a)] * size
        self.hist = [0] * 256
        width = Histogram.width

        height = int(round(size / width))
        e = ''
        bufsize = 0
        for mapped, buf in buffers:
            if mapped:
                bufsize += len(buf)
                for c in buf:
                    e += c
                    self.hist[ord(c)] += 1
        self.entropy = H(e)
        self.max_count = max(self.hist)
        cursor_x = mouse_offs % width

        if self.max_count > 0 and height > 0:
            bars = []
            for i in xrange(len(self.hist)):
                count = self.hist[i]
                bars.append(int(round((count/float(self.max_count))*height)))

            for i in xrange(len(bars)):
                dst_y = bars[i]
                for y in xrange(dst_y):
                    colors[height*width - width+i - y*width] = (True, 0xf2f0f0 if i == cursor_x else [0xffad00,0xc10000][i%2])

        self.annotations = [(None, None, 'Start: 0x%X' % addr, 0xf2f0f0),
        (None, None, 'End: 0x%X' % (addr+bufsize), 0xf2f0f0),
        (None, None, 'Size: 0x%X' % (bufsize), 0xf2f0f0),
        (None, None, '', None),
        (None, None, 'Entropy: %f' % float(self.entropy), 0xf2f0f0),
        (None, None, 'Byte: 0x%02X (%d/%d)' % (cursor_x, self.hist[cursor_x], self.max_count), 0xf2f0f0)]

        return colors

    def on_get_tooltip(self, addr, size, mouse_offs):
        i = mouse_offs % Histogram.width
        tooltip = '%02X: %d occurences' % (i, self.hist[i])

        return tooltip


def FILTER_INIT(pw):
    return Histogram(pw)
    
def FILTER_EXIT():
    return