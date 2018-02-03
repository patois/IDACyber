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
    zoom = 3
    link_pixel = False
    show_address_range = False

    def __init__(self, pw):
        self.annotations = None
        self.pw = pw
        self.loc = None
        self.entropy = 0.0

    def on_mb_click(self, event, addr, size, mouse_offs):
        if event.button() == Qt.RightButton:
            if self.loc:
                self.loc = None
                self.annotations = None
            else:
                self.loc = (mouse_offs % Histogram.width, 0)
        return


    def on_get_annotations(self, address, size, mouse_offs):
        return self.annotations

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        hist = [0] * 256
        width = Histogram.width

        height = size / width
        e = ""
        for mapped, buf in buffers:
            if mapped:
                for c in buf:
                    e += c
                    hist[ord(c)] += 1
        self.entropy = H(e)

        self.annotations = [(None, None, "Enropy: %f" % float(self.entropy), 0xf2f0f0),
        (None, None, "Start %X" % addr, 0xf2f0f0),
        (None, None, "End: %X" % (addr+size), 0xf2f0f0),
        (self.loc, 0xf2f0f0, "test", 0xf2f0f0)]

        max_count = max(hist)

        for cur_y in xrange(1,(size/width)+1):
            for i in xrange(256):
                count = hist[i]
        
                col = 0x193d5a
                if count:
                    if cur_y > height-((count/float(max_count))*height):
                        col = 0xffad00
                colors.append((True, col))

        return colors
    
def FILTER_INIT(pw):
    return Histogram(pw)
    
def FILTER_EXIT():
    return