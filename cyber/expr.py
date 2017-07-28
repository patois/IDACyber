from PyQt5.QtGui import qRgb
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import askstr, warning

class xpression(ColorFilter):
    name = "expression"
    highlight_cursor = True
    help = None

    def __init__(self):
        self.xpr = "c, c, c"

    def _set_user_expr(self):
        while True:
            xpr = askstr(0, self.xpr, "Please enter expression")
            if xpr is None:
                break
            
            try:
                c = 0
                r, g, b = eval(xpr)
                self.xpr = xpr
                break
            except:
                warning("Invalid expression!")
                continue



    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.RightButton:
            self._set_user_expr()

    def render_img(self, buf, addr, mouse_offs):
        colors = []
        for c in buf:
            c = ord(c) & 0xFF
            r, g, b = eval(self.xpr)
            colors.append(qRgb(r&0xFF, g&0xFF, b&0xFF))
        return colors

def FILTER_ENTRY():
    return xpression()
