from PyQt5.QtGui import qRgb, QColor
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_byte, get_item_head, get_item_end
from ida_name import get_name
from ida_lines import generate_disasm_line, GENDSM_FORCE_CODE, GENDSM_REMOVE_TAGS
from ida_ua import can_decode, insn_t, decode_insn
from ida_idp import is_ret_insn
from ida_segment import getseg, SEGPERM_EXEC

class VROP(ColorFilter):
    name = "VisualROP"
    highlight_cursor = False
    help =  "Highlight return instructions"
    zoom = 5
    width = 32

    def __init__(self):
        # "Dark Hope Color Palette" http://www.color-hex.com/color-palette/46221
        self.colormap = [0x00321c, 0x004c2b, 0x006539, 0x007f47, 0x009856]
        self.ptrcol = 0xb2b2b2 #0xcccccc
        self.ret_locs = []
        self.threshold = 9

    def _is_ret(self, x):
        if can_decode(x):
            insn = insn_t()
            inslen = decode_insn(insn, x)
            if inslen > 0 and is_ret_insn(insn):
                return True
        return False

    def on_process_buffer(self, buffers, addr,size, mouse_offs):
        colors = []
        goffs = 0
        self.ret_locs = []
        nret = 0
        colidx = 0

        for mapped, buf in buffers:
            if mapped:        
                for i in xrange(len(buf)):           
                    c = ord(buf[i])
                    if self._is_ret(addr+goffs+i):
                        self.ret_locs.append((nret, colidx, addr+goffs+i))
                        nret += 1
                        col = ~((self.colormap[c/(0xff/(len(self.colormap)-1))])&0xFFFFFF)
                        """if nret <= self.threshold:
                            col = QColor(col).lighter(140).rgb()"""
                    else:
                        col = self.colormap[c/(0xff/(len(self.colormap)-1))]
                    colors.append((True, col))
                    colidx += 1
            else:
                for i in xrange(len(buf)):
                    colors.append((False, None))
                    colidx += 1

            goffs += len(buf)

        if nret:
            offs = self._get_selection_offs()
            end = min(offs+self.threshold+1, nret)
            for i in xrange(offs, end):
                idx, colidx, _ = self.ret_locs[i]
                mapped, col = colors[colidx]
                colors[colidx] = (mapped, QColor(col).lighter(140).rgb())
        return colors

    def _get_selection_offs(self):
        offs = 0
        nret = len(self.ret_locs)
        if nret/2 > self.threshold/2:
            offs = nret/2 - self.threshold/2
        return offs


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
                textcol = self.ptrcol
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
    return VROP()
    
def FILTER_EXIT():
    return