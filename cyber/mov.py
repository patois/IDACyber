from PyQt5.QtGui import qRgb, QColor
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_bytes import get_item_size, get_byte, get_item_head, get_item_end, get_full_flags
from idc import is_code
from ida_lines import generate_disasm_line, GENDSM_FORCE_CODE, GENDSM_REMOVE_TAGS
from ida_ua import can_decode, decode_insn, insn_t, o_mem, o_phrase, o_displ
from ida_idaapi import BADADDR
import ida_allins
import ida_idp

ACC_READ = 0
ACC_WRITE = 1

class MovFilter(ColorFilter):
    name = 'Highight Load/Store'
    help = 'Highlight memory load/store (mov) instructions.'

    def __init__(self):
        # s+b teal Color Palette http://www.color-hex.com/color-palette/309
        self.colormap = [0x007777, 0x006666, 0x005555, 0x004444, 0x003333]
        self.insn_colors = {ACC_READ:0x00cc37, ACC_WRITE:0xCC3700}
        self.ptrcol = 0xe2e2e2
        self.txtcol = 0xb2b2b2
        self.annotations = []
        self.threshold = 9
        self.insn = insn_t()

    def _ins2color(self, addr):
        col = _len = 0
        acc = -1

        head = get_item_head(addr)
        if can_decode(head):
            f = get_full_flags(head)
            if is_code(f):
                _len = decode_insn(self.insn, head)
                if _len:
                    if self.insn.itype in [ida_allins.NN_mov]: # TODO: add more instructions
                        if self.insn.Op1.type in [o_mem, o_phrase, o_displ]:
                            acc = ACC_WRITE
                            col = self.insn_colors[acc]
                        elif self.insn.Op2.type in [o_mem, o_phrase, o_displ]:
                            acc = ACC_READ
                            col = self.insn_colors[acc]
                        else:
                            acc = -1

        return (col, _len, acc)

    def _get_selection_offs(self):
        offs = 0
        ann_cnt = len(self.annotations)
        if ann_cnt/2 > self.threshold/2:
            offs = ann_cnt/2 - self.threshold/2
        return offs

    def on_get_annotations(self, address, size, mouse_offs):
        caption = "Mov instructions:"
        spaces = 40*'-'
        ann = [(None, None, caption, self.colormap[-1])]
        if len(self.annotations):
            i = 0
            offs = self._get_selection_offs()
            ann_cnt = len(self.annotations)
            for x in xrange(offs,ann_cnt):
                _, acc, ea = self.annotations[x]
                textcol = self.txtcol
                ann.append((ea, self.insn_colors[acc], "   %X:  %s" % (ea, generate_disasm_line(ea, GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS)), self.insn_colors[acc]))
                i += 1
                if i > self.threshold:
                    ann.append((None, None, "<%d more not shown>" % (len(self.annotations) - i), self.colormap[-1]))
                    break
        return ann


    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        goffs = 0
        ann_n = 0
        self.annotations = []

        for is_mapped, buf in buffers:
            if is_mapped:
                i = 0
                blen = len(buf)
                while i < blen:
                    col, _len, acc = self._ins2color(addr+goffs+i)
                    if acc != -1 and col and _len:
                        maxlen = min(blen-i, _len)
                        self.annotations.append((ann_n, acc, addr+goffs+i))
                        ann_n += 1
                        for j in xrange(maxlen):
                            colors.append((True, col))
                        i += maxlen
                    else:
                        col = self.colormap[ord(buf[i])/(0xff/(len(self.colormap)-1))]
                        colors.append((True, col))
                        i += 1
            else:
                # indicate transparent area
                for i in xrange(len(buf)):
                    colors.append((False, None))

            goffs += len(buf)
        return colors

def FILTER_INIT(pw):
    if ida_idp.ph.id != ida_idp.PLFM_386:
        return None
    return MovFilter()
    
def FILTER_EXIT():
    return