from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt
from idacyber import ColorFilter
from ida_kernwin import askstr, warning

class xpression(ColorFilter):
    name = "expression"

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



    def on_mb_click(self, addr, button):
        if button == Qt.RightButton:
            self._set_user_expr()

    def do_filter(self, buf, addr):
        colors = []
        for c in buf:
            c = ord(c) & 0xFF
            r, g, b = eval(self.xpr)
            colors.append(QColor(r&0xFF, g&0xFF, b&0xFF))
        return colors

def FILTER_ENTRY():
    return xpression()
