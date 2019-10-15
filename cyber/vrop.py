from PyQt5.QtGui import qRgb, QColor
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_byte, get_item_head, get_item_end
from ida_name import get_name
from ida_lines import generate_disasm_line, GENDSM_FORCE_CODE, GENDSM_REMOVE_TAGS
from ida_ua import can_decode, insn_t, decode_insn
from ida_idp import is_ret_insn
from ida_segment import getseg, SEGPERM_EXEC
from ida_kernwin import register_timer, unregister_timer, warning

class VROP(ColorFilter):
    name = "VisualROP"
    highlight_cursor = False
    help =  "Highlight return instructions.\n\nRMB toggles cyber mode."
    zoom = 10
    width = 16

    def __init__(self, pw):
        # "Dark Hope Color Palette" http://www.color-hex.com/color-palette/46221
        self.colormap = [0x00321c, 0x004c2b, 0x006539, 0x007f47, 0x009856]
        self.ptrcol = 0xe2e2e2
        self.txtcol = 0xb2b2b2
        self.ret_locs = []
        self.threshold = 9
        self.pw = pw
        self.torch = False
        self.timer = None
        self.numframes = 4
        self.maxbrightness = 100
        self.factor = self.maxbrightness/self.numframes
        self.flicker_values = list(range(1, self.numframes+1)+range(self.numframes-1,0,-1))
        self.flicker_idx = self.flicker_values[self.numframes/2]
        self.ms = 200

        if self.torch:
            self._enable_timer()

        return

    def _enable_timer(self):
        if self.timer:
            unregister_timer(self.timer)
        self.timer = register_timer(self.ms, self._flicker_cb)
        return

    def _is_ret(self, x):
        if can_decode(x):
            insn = insn_t()
            inslen = decode_insn(insn, x)
            if inslen > 0 and is_ret_insn(insn):
                return True
        return False

    def _apply_shadow_fx(self, color, idx, width, total):
        col = color
        rows_total = total / width
        maxrows = rows_total / 4
        cur_row = idx / width
        shadow_blocksize = maxrows*width
        maxdarkness = 70

        if cur_row*width < (shadow_blocksize):
            factor = (maxrows-cur_row)
            darkness = factor*maxdarkness/float(maxrows)
            col = QColor(col).darker(100+darkness).rgb()
        elif cur_row*width >= rows_total*width-shadow_blocksize:
            factor = (maxrows-(rows_total-cur_row))
            darkness = factor*maxdarkness/float(maxrows)
            col = QColor(col).darker(100+darkness).rgb()       
        return col

    def _flicker_cb(self):
        self.flicker_idx = (self.flicker_idx + 1) % len(self.flicker_values)
        if self.pw:
            self.pw.on_filter_request_update()
        return self.ms

    def on_mb_click(self, event, addr, size, mouse_offs):
        if event.button() == Qt.RightButton:
            if self.torch:
                self.flicker_idx = self.flicker_values[self.numframes/2]
                if self.timer:
                    unregister_timer(self.timer)
                    self.timer = None
                else:
                    warning("!!!Bug!!!")
            else:
                self._enable_timer()
            self.torch = not self.torch
            self.pw.on_filter_request_update()
        return

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        goffs = 0
        self.ret_locs = []
        nret = 0
        colidx = 0
        width = self.pw.get_width()

        for mapped, buf in buffers:
            if mapped:        
                for i in xrange(len(buf)):
                    c = ord(buf[i])
                    if self._is_ret(addr+goffs+i):
                        self.ret_locs.append((nret, colidx, addr+goffs+i))
                        nret += 1
                        col = (~((self.colormap[c/(0xff/(len(self.colormap)-1))])&0xFFFFFF) & 0xFFFFFFFF)
                    else:
                        col = self.colormap[c/(0xff/(len(self.colormap)-1))]
                    colors.append((True,  col))
                    colidx += 1
            else:
                for i in xrange(len(buf)):
                    colors.append((False, None))
                    colidx += 1

            goffs += len(buf)

        # apply glow
        if nret:
            offs = self._get_selection_offs()
            end = min(offs+self.threshold+1, nret)
            cur_item_idx = 0
            for i in xrange(offs, end):
                _, colidx, _ = self.ret_locs[i]
                for row in xrange(-4, 5):
                    targetpxl_idx = colidx+(width*row)
                    for neighbour in xrange(-4, 5):
                        realpxl_idx = targetpxl_idx+neighbour
                        brightness = (abs(row)+abs(neighbour))*10
                        # check top, bottom, left, right borders
                        if realpxl_idx > 0 and realpxl_idx < size and realpxl_idx/width == targetpxl_idx/width:
                            mapped, col = colors[realpxl_idx]

                            if mapped:
                                # uncomment for "debugging"
                                # col = 0xFF0000
                                flicker = self.maxbrightness
                                if self.torch:
                                    flicker = self.flicker_values[self.flicker_idx]*self.factor
                                colors[realpxl_idx] = (mapped, QColor(col).lighter(max(100, 100-brightness+flicker)).rgb())
                cur_item_idx += 1


        # apply shadow
        colidx = 0
        for mapped, col in colors:
            if mapped:
                colors[colidx] = (mapped, self._apply_shadow_fx(col, colidx, width, size))
            colidx += 1
        return colors

    def _get_selection_offs(self):
        offs = 0
        nret = len(self.ret_locs)
        if nret/2 > self.threshold/2:
            offs = nret/2 - self.threshold/2
        return offs

    def on_activate(self, idx):
        self._enable_timer()
        return

    def on_deactivate(self):
        if self.timer:
            unregister_timer(self.timer)
            self.timer = None
        return

    def on_get_annotations(self, address, size, mouse_offs):
        caption = "Return instructions:"
        spaces = 40*'-'
        ann = [(None, None, caption, self.colormap[-1])]
        if len(self.ret_locs):
            i = 0
            offs = self._get_selection_offs()
            nret = len(self.ret_locs)
            for x in xrange(offs,nret):
                _, __, ret = self.ret_locs[x]
                seg = getseg(ret)
                textcol = self.txtcol
                if seg is not None:
                    if not seg.perm & SEGPERM_EXEC:
                        # red text color if ret not within executable segment
                        textcol = 0xEE0000
                ann.append((ret, self.ptrcol, "   %X  [%s]" % (ret, generate_disasm_line(ret, GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS)), textcol))
                i += 1
                if i > self.threshold:
                    ann.append((None, None, "<%d more not shown>" % (len(self.ret_locs) - i), self.colormap[-1]))
                    break
        return ann

def FILTER_INIT(pw):
    return VROP(pw)
    
def FILTER_EXIT():
    return