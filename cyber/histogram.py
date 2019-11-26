from math import log
from idacyber import ColorFilter
import ida_kernwin
from PyQt5.QtCore import Qt

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
    help = """This filter creates a histogram.
Please select a range of bytes in the disassembly view.
MMB cycles through different palettes."""
    width = 256
    lock_width = True
    zoom = 2
    link_pixel = False
    support_selection = True
    highlight_cursor = False
    disable_data = True
    show_address_range = False

    def __init__(self):
        self.entropy = 0.0
        self.max_count = 0
        self.hist = []
        self.bufsize = 0
        self.palettes = [[0x050f42, 0x084c61, 0x0d94a3, 0xd34410, 0xff6e00],
                        [0x17313b, 0x414f47, 0x866d5c, 0xd5aaaa, 0xfff3e3],
                        list(reversed([0xc8bd00, 0xa6aaa5, 0x8faebe, 0x005b95, 0x010e1f])),
                        [0x100e15, 0x323e53, 0x408fb4, 0xbddfef, 0x64566e],
                        [0x0d0e12, 0x073245, 0x4886af, 0x83c1e8, 0xfcd5ce],
                        [0x010000, 0xa74c00, 0xffa100, 0xffd300, 0xf1f2f1],
                        [0x421930, 0x7c1e3b, 0xb44346, 0xd88e6c, 0xf6e7ce],
                        [0x002338, 0x009dd2, 0xffd898, 0xffca03, 0xa83a01],
                        [0x050831, 0x133072, 0xd5e6f7, 0xd5adfb, 0xf90052],
                        list(reversed([0x007f9f, 0x019c7c, 0x009f00, 0x006332, 0x001b00])),
                        [0x00070a, 0x294552, 0x597884, 0xacc4ce, 0x9eb9b3]]
        # default palette
        self.cur_palette = 0

    def on_mb_click(self, event, addr, size, mouse_offs):
        button = event.button()
        if button == Qt.MiddleButton:
            self.cur_palette = (self.cur_palette + 1) % len(self.palettes)
            self.palette = self.palettes[self.cur_palette]

    def on_get_annotations(self, address, size, mouse_offs):
        cursor_x = mouse_offs % Histogram.width
        annotations = None
        if self.bufsize and cursor_x in range(len(self.hist)):
            count = self.hist[cursor_x]
            annotations = [(None, None, '', None),
            (None, None, '[Entropy]', None),
            (None, None, ' Entropy: %f' % float(self.entropy), self.palettes[self.cur_palette][3]),
            (None, None, '', None),
            (None, None, '[Address Range]', None),
            (None, None, ' Start: 0x%X' % address, self.palettes[self.cur_palette][3]),
            (None, None, ' End: 0x%X' % (address+self.bufsize), self.palettes[self.cur_palette][3]),
            (None, None, ' Size: 0x%X' % (self.bufsize), self.palettes[self.cur_palette][3]),
            (None, None, '', None),
            (None, None, '[Misc info]', None),
            (None, None, ' Current Byte: 0x%02X x %d (%.2f%%)' % (cursor_x, count, (count/float(self.bufsize))*100.0), self.palettes[self.cur_palette][3]),
            (None, None, ' Palette: %d/%d' % (self.cur_palette+1, len(self.palettes)),  self.palettes[self.cur_palette][3])]
        return annotations

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = [(True, self.palettes[self.cur_palette][0])] * size
        self.hist = [0] * 256
        width = Histogram.width

        height = round(size / width)
        e = ""
        self.bufsize = 0
        for mapped, buf in buffers:
            if mapped:
                self.bufsize += len(buf)
                for c in buf:
                    e += chr(c)
                    self.hist[c] += 1
        self.entropy = H(e)
        self.max_count = max(self.hist)
        cursor_x = mouse_offs % width

        if self.max_count and height:
            bars = []
            for i in range(len(self.hist)):
                count = self.hist[i]
                bars.append(round((count/float(self.max_count))*height))

            for i in range(len(bars)):
                dst_y = bars[i]
                for y in range(dst_y):
                    colors[height*width - width+i - y*width] = (True, self.palettes[self.cur_palette][-1] if i == cursor_x else self.palettes[self.cur_palette][1+i%2])

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