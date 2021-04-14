from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import ask_text, warning
from types import FunctionType

class Prototype(ColorFilter):
    name = "Prototype"
    help = "Right click: edit current filter function"
    highlight_cursor = False

    def __init__(self, pw):
        self.pw = pw
        self.func_call = None
        self.func_def=(
"""
def process(base, offs, b, size, width, moffs):
  # print("%x+%x: %02x (total pxls %d, width %d, mouse pos %d)" % (base, offs, b, size, width, moffs))
  # return (b,b,b)

  if (b == 0x70 or b == 0x47):
    # detect potential thumb-mode pattern
    color = (0x59, 0x7c, 0x92)
  elif (b & 0xf0 == 0xe0):
    # detect potential ARM pattern
    color = (0x00, 0x40, 0x67)
  else:
    # default color
    color = (0x00, 0x10, 0x1b)

  # cross-hair
  if offs%width == moffs%width or int(offs/width) == int(moffs/width):
    color = (min(color[0]+0x00,0xff),
             min(color[1]+0x04,0xff),
             min(color[2]+0x04,0xff))
  return color""")

        self._compile(self.func_def)

    def _compile(self, text):
        self.func_def = text
        try:
            self.func_code = compile(text, "", "exec")
            self.func_call = FunctionType(self.func_code.co_consts[0], globals(), "")
            return (True, "")
        except Exception as e:
            return (False, e)
        return (False, "")
            
    def _set_user_func(self):
        while True:
            func_def = ask_text(0, self.func_def, "Please define function (must return tuple(RR,GG,BB) format")
            if func_def is None:
                break
            res, s = self._compile(func_def)
            if res:
                break
            warning("%s" % s)

    def on_mb_click(self, event, addr, size, mouse_offs):
        if event.button() == Qt.RightButton:
            self._set_user_func()

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        width = self.pw.get_pixel_qty_per_line()

        for mapped, buf in buffers:
            if mapped:
                for offs in range(len(buf)):
                    try:
                        r, g, b = self.func_call(
                            addr,
                            offs,
                            buf[offs]&0xff,
                            size,
                            width,
                            mouse_offs)
                        colors.append((True, qRgb(r&0xFF, g&0xFF, b&0xFF)))
                    except:
                        colors.append((False, None))
            else:
                colors += [(False, None)]*len(buf)
        return colors

def FILTER_INIT(pw):
    return Prototype(pw)
    
def FILTER_EXIT():
    return