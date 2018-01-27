import os
from PyQt5.QtWidgets import QWidget, QApplication, QCheckBox, QLabel, QComboBox, QSizePolicy
from PyQt5.QtGui import QPainter, QColor, QFont, QPen, QPixmap, QImage, qRgb, QPainterPath
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QRect, QSize, QPoint
from idaapi import *
from ida_kernwin import msg
from os import path
import copy

__author__ = 'Dennis Elser'

banner = """
.___ .______  .______  ._______ ____   ____._______ ._______.______  
: __|:_ _   \ :      \ :_.  ___\\   \_/   /: __   / : .____/: __   \ 
| : ||   |   ||   .   ||  : |/\  \___ ___/ |  |>  \ | : _/\ |  \____|
|   || . |   ||   :   ||    /  \   |   |   |  |>   \|   /  \|   :  \ 
|   ||. ____/ |___|   ||. _____/   |___|   |_______/|_.: __/|   |___\ 
|___| :/          |___| :/                             :/   |___|   

"""


#   TODO:
#   * refactor
#   * colorfilter: improve/refactor callbacks (do not process gaps)?
#   * colorfilter: improve arrows
#   * colorfilter: return filter flags (controls behavior of graph etc)
#   * fix keyboard controls bug
#   * fix multiple "Dbg" filter instances bug
#   * optimize redrawing?
#   * load filters using "require"
#   * add grid?
#   * use internal scaling etc?
#   * store current settings in netnode

class ColorFilter():
    name = None
    highlight_cursor = True
    help = None

    def on_activate(self, idx, pw):
        pass

    def on_deactivate(self):
        pass

    def on_mb_click(self, button, addr, mouse_offs):
        pass
    
    def render_img(self, buffers, addr, mouse_offs):
        return []

    def get_tooltip(self, addr, mouse_offs):
        return None

    def get_annotations(self, addr, size, mouse_offs):
        return None

# -----------------------------------------------------------------------

class ScreenEAHook(View_Hooks):
    def __init__(self):
        View_Hooks.__init__(self)
        self.sh = SignalHandler()
        self.new_ea = self.sh.ida_newea
    
    def view_loc_changed(self, widget, curloc, prevloc):
        if curloc is not prevloc:
            self.new_ea.emit()

# -----------------------------------------------------------------------

class SignalHandler(QObject):    
    pw_statechanged = pyqtSignal()
    ida_newea = pyqtSignal()

# -----------------------------------------------------------------------

class IDBBufHandler():
    def __init__(self, loaderSegmentsOnly=False):
        pass

    def get_buffers(self, ea, count=0):
        buffers = []
        base = offs = 0
        i = 0
        base = offs = 0

        result = get_bytes_and_mask(ea, count)
        if result:
            buf, mask = result
            for m in xrange(len(mask)):
                b = ord(mask[m])
                if i == 0:
                    ismapped = (b&1) != 0
                for j in xrange(8):
                    bitset = ((b>>j) & 1) != 0
                    if bitset != ismapped:
                        offs = i+j
                        buffers.append((ismapped, buf[base:offs]))
                        base = i+j
                        ismapped = not ismapped

                if j == 7:
                    offs = i+j+1
                    if m == len(mask)-1:
                        buffers.append((ismapped, buf[base:offs]))
                i += 8
        return buffers

    def get_base(self, ea):
        base = BADADDR
        qty = get_segm_qty()
        for i in xrange(qty):
            seg = getnseg(i)
            if seg and seg.contains(ea):
                base = seg.startEA
                break
        return base
        

# -----------------------------------------------------------------------
    
class PixelWidget(QWidget):
    def __init__(self, form, bufhandler):
        super(PixelWidget, self).__init__()

        self.form = form
        self.pixelSize = 3
        self.maxPixelsPerLine = 64
        self.maxPixelsTotal = 0
        self.old_mouse_y = 0
        self.key = None
        self.buffers = None
        self.offs = 0
        self.base = 0
        self.fm = None
        self.mouseOffs = 0
        self.numbytes = 0
        self.sync = True
        self.bh = bufhandler
        self.elemX = 0
        self.elemY = 0
        self.rect_x = 0
        
        self.setMouseTracking(True)        
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.sh = SignalHandler()
        self.statechanged = self.sh.pw_statechanged
        
        self.show()

    def paintEvent(self, event):
        # set leftmost x-coordinate of graph
        self.rect_x = (self.rect().width() / 2) - ((self.maxPixelsPerLine * self.pixelSize) / 2)

        qp = QPainter()
        qp.begin(self)

        # fill background
        qp.fillRect(self.rect(), Qt.black)

        # draw addresses
        qp.setPen(QColor(Qt.white))
        top = "%X:" % self.get_address()
        bottom = "%X:" % (self.get_address() + ((self.maxPixelsTotal / self.maxPixelsPerLine) - 1) * self.maxPixelsPerLine)
        qp.drawText(self.rect_x - qp.fontMetrics().width(top) - self.pixelSize, qp.fontMetrics().height(), top)
        qp.drawText(self.rect_x - qp.fontMetrics().width(bottom) - self.pixelSize, self.rect().height() - qp.fontMetrics().height() / 2, bottom)

        # use colorfilter to render image
        img = self.render_image()

        # draw image
        if img is not None:    
            qp.drawImage(QRect(QPoint(self.rect_x, 0), 
                QPoint(self.rect_x + self.maxPixelsPerLine * self.pixelSize, (self.maxPixelsTotal / self.maxPixelsPerLine) * self.pixelSize)),
                img)

        # get and draw annotations and pointers
        annotations = self.fm.get_annotations(self.get_address(), self.get_bytes_total(), self.mouseOffs)
        if annotations:
            self.render_annotations(qp, annotations)

        qp.end()       

    def render_image(self, cursor=True):
        size = self.size()
        self.maxPixelsTotal = self.maxPixelsPerLine * (size.height() / self.pixelSize)
        self.buffers = self.bh.get_buffers(self.base + self.offs, self.maxPixelsTotal)       
        self.numbytes = self.maxPixelsTotal
        img = QImage(self.maxPixelsPerLine, size.height() / self.pixelSize, QImage.Format_RGB32)
        addr = self.base + self.offs
        pixels = self.fm.render_img(self.buffers, addr, self.mouseOffs)

        x = y = 0
        # transparacy effect for unmapped bytes
        transparency_dark = [qRgb(0x2F,0x4F,0x4F), qRgb(0x00,0x00,0x00)]
        for mapped, pix in pixels:
            if not mapped:
                if pix is None:
                    pix = transparency_dark[(x&2 != 0) ^ (y&2 != 0)]
            img.setPixel(x, y, pix)
            x = (x + 1) % self.maxPixelsPerLine
            if not x:
                y = y + 1

        if cursor and self.fm.highlight_cursor:
            p = QPoint(self.get_elem_x(), self.get_elem_y())
            img.setPixel(p, ~(img.pixelColor(p)).rgb())

        return img

    def render_annotations(self, qp, annotations=[]):
        base_x = self.rect_x + self.maxPixelsPerLine * self.pixelSize + 20
        base_y = qp.fontMetrics().height()
        offs_x = 5
        offs_y = base_y
        a_offs = 10

        for coords, arr_color, ann, txt_color in annotations:
            # draw arrow (experimental / WIP)
            qp.setPen(QColor(Qt.white if txt_color is None else txt_color))
            qp.drawText(base_x+10, (base_y+offs_y)/2, ann)
            target_x = target_y = None
            if coords:
                if isinstance(coords, tuple):
                    target_x, target_y = coords
                else:
                    ptr = self.get_coords_by_address(coords)
                    if ptr:
                        target_x, target_y = ptr

                if target_x is not None and target_y is not None:
                    target_x *= self.pixelSize
                    target_y *= self.pixelSize

                    qp.setPen(QColor(Qt.white if arr_color is None else arr_color))
                    path = QPainterPath()
                    path.moveTo(base_x+offs_x, (base_y+offs_y)/2-base_y/2)

                    path.lineTo(base_x+offs_x - 4 - a_offs, (base_y+offs_y)/2-base_y/2)  # left
                    path.lineTo(base_x+offs_x - 4 - a_offs, ((target_y/10)*9) + self.pixelSize/2) # down
                    path.lineTo(self.rect_x + target_x + self.pixelSize / 2, ((target_y/10)*9) + self.pixelSize/2) # left
                    path.lineTo(self.rect_x + target_x + self.pixelSize / 2, target_y + self.pixelSize/2) # down
                    a_offs = max(a_offs-2, 0)
                    qp.drawPath(path)
            offs_y += 2*base_y + 5
        return

    def filter_request_update(self, ea=None, center=True):
        if not ea:
            self.repaint()
        else:
            curea = self.get_address()
            if ea < curea or ea >= curea + self.get_pixels_total():
                # TODO: verify that ea is valid after following operation
                if center:
                    ea -= self.get_pixels_total()/2
                self.set_addr(ea)
            else:
                self.repaint()


    def keyPressEvent(self, event):
        update = False
        
        if self.key is None:
            self.key = event.key()
        else:
            if self.key == Qt.Key_Control:
                if event.key() == Qt.Key_Plus:
                    self.set_zoom_delta(1)
                    update = True
                elif event.key() == Qt.Key_Minus:
                    self.set_zoom_delta(-1)
                    update = True
            elif self.key == Qt.Key_Shift:
                if event.key() == Qt.Key_Plus:
                    self.set_offset_delta(-self.get_width())
                    update = True
                elif event.key() == Qt.Key_Minus:
                    self.set_offset_delta(self.get_width())
                    update = True


        if self.key == Qt.Key_G:
            addr = AskAddr(self.base + self.offs, 'Jump to address')
            if addr is not None:
                jumpto(addr)
        elif self.key == Qt.Key_F2:
            hlp = self.fm.help
            if hlp is None:
                hlp = "Help unavailable"
            info(hlp+"\n\n")
            self.key = None # workaround fixme
        elif self.key == Qt.Key_F12:
            img = self.render_image(cursor = False)
            done = False
            i = 0
            while not done:
                fname = 'IDACyber_%04d.bmp' % i
                if not path.isfile(fname):
                    if img.save(fname):
                        msg('File exported to %s\n' % fname)
                    else:
                        warning('Error exporting screenshot to %s.' % fname)
                        self.key = None # workaround fixme
                    done = True
                i += 1

        elif self.key == Qt.Key_PageDown:
            self.set_offset_delta(-self.get_pixels_total())
            update = True

        elif self.key == Qt.Key_PageUp:
            self.set_offset_delta(self.get_pixels_total())
            update = True

        elif self.key == Qt.Key_Plus:
            self.set_offset_delta(-1)
            update = True

        elif self.key == Qt.Key_Minus:
            self.set_offset_delta(1)
            update = True

        if update:
            if self.get_sync_state():
                jumpto(self.base + self.offs)
                self.activateWindow()
                self.setFocus()
            self.statechanged.emit()
            self.repaint()


    def keyReleaseEvent(self, event):
        if self.key == event.key():
            self.key = None
        
    def mousePressEvent(self, event):
        self.old_mouse_y = event.pos().y()
        self.fm.on_mb_click(event.button(), self.get_address(), self.mouseOffs)

    def mouseReleaseEvent(self, event):
        if self.get_sync_state():
            jumpto(self.base + self.offs)
            self.activateWindow()
            self.setFocus()
            self.statechanged.emit()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            addr = self.base + self.offs + self._get_offs_by_pos(event.pos())
            jumpto(addr)

    def wheelEvent(self, event):
        delta = event.angleDelta().y()/120

        # zoom
        if self.key == Qt.Key_Control:
            self.set_zoom_delta(delta)

        # width            
        elif self.key == Qt.Key_X:
            self.set_width_delta(delta)

        # offset (fine)
        elif self.key == Qt.Key_Shift:
            self.set_offset_delta(delta)

            if self.get_sync_state():
                jumpto(self.base + self.offs)
                self.activateWindow()
                self.setFocus()

        elif self.key == Qt.Key_H:
            less = delta < 0
            w = -16 if less else 16
            self.set_width((self.get_width() & 0xFFFFFFF0) + w)

        # offset (coarse)
        else:
            self.set_offset_delta(delta * self.maxPixelsPerLine)
            
            if self.get_sync_state():
                jumpto(self.base + self.offs)
                self.activateWindow()
                self.setFocus()

        self.statechanged.emit()
        self.repaint()
        
    def mouseMoveEvent(self, event):
        x = event.pos().x()
        y = event.pos().y()
        
        if event.buttons() == Qt.NoButton:
            self._update_mouse_coords(event.pos())
            self.mouseOffs = self._get_offs_by_pos(event.pos())

            self.setToolTip(self.fm.get_tooltip(self.get_address(), self.mouseOffs))

        # zoom
        elif self.key == Qt.Key_Control:
            self.set_zoom_delta(-1 if y > self.old_mouse_y else 1)

        # width
        elif self.key == Qt.Key_X:
            self.set_width_delta(-1 if y > self.old_mouse_y else 1)

        elif self.key == Qt.Key_H:
            less = y > self.old_mouse_y
            delta = -16 if less else 16
            self.set_width((self.get_width() & 0xFFFFFFF0) + delta)

        # scrolling (offset)
        elif y != self.old_mouse_y:
            # offset (fine)
            delta = y - self.old_mouse_y

            # offset (coarse)
            if self.key != Qt.Key_Shift:
                delta *= self.get_width()
                
            self.set_offset_delta(delta)

        self.old_mouse_y = y
        self.x = x
        self.statechanged.emit()
        self.repaint()

    def set_sync_state(self, sync):
        self.sync = sync

    def get_sync_state(self):
        return self.sync
    
    def set_filter(self, filter, idx):
        if self.fm:
            self.fm.on_deactivate()
        self.fm = filter
        self.fm.on_activate(idx, self)
        self.repaint()

    def set_addr(self, ea):
        base = self.bh.get_base(ea)
        self._set_base(base)
        self._set_offs(ea - base)
        self.repaint()

    def get_zoom(self):
        return self.pixelSize

    def get_width(self):
        return self.maxPixelsPerLine

    # return total number of bytes in current view
    def get_bytes_total(self):
        return self.numbytes
    
    def get_pixels_total(self):
        return self.maxPixelsTotal

    def get_address(self):
        return self.base + self.offs

    def get_cursor_address(self):
        return self.get_address() + self.mouseOffs

    def get_coords_by_address(self, address):
        base = self.get_address()
        # if address is visible in current window
        if address >= base and address < base + self.get_pixels_total():
            offs = address - base
            x = offs % self.get_width()
            y = offs / (self.get_width())
            return (x, y)
        return None

    def set_zoom_delta(self, dzoom):
        self.pixelSize = max(1, self.pixelSize + dzoom)

    def set_width(self, width):
        self.maxPixelsPerLine = max(1, width)

    def set_width_delta(self, dwidth):
        self.maxPixelsPerLine = max(1, self.maxPixelsPerLine + dwidth)

    def set_offset_delta(self, doffs):
        newea = self.base + self.offs - doffs
        minea = get_inf_structure().get_minEA()
        maxea = get_inf_structure().get_maxEA()
        if doffs < 0:
            delta = doffs if newea < maxea else doffs - (maxea - newea)
        else:
            delta = doffs if newea >= minea else doffs - (minea - newea)
        self._set_offs(self.offs - delta)

    def _get_offs_by_pos(self, pos):
        elemX = self.get_elem_x()
        elemY = self.get_elem_y()
        offs = elemY * self.maxPixelsPerLine + elemX
        return offs

    def _update_mouse_coords(self, pos):
        self.elemX = max(0, min((max(0, pos.x() - self.rect_x)) / self.pixelSize, self.maxPixelsPerLine - 1))
        self.elemY = min(pos.y() / self.pixelSize, self.maxPixelsTotal / self.maxPixelsPerLine - 1)

    def get_elem_x(self):
        return self.elemX

    def get_elem_y(self):
        return self.elemY

    def _set_offs(self, offs):
        self.offs = offs

    def _set_base(self, ea):
        self.base = ea


# -----------------------------------------------------------------------


class IDACyberForm(PluginForm):
    idbh = None
    hook = None
    windows = []

    def __init__(self):
        if IDACyberForm.idbh is None:
            IDACyberForm.idbh = IDBBufHandler(True)

        if IDACyberForm.hook is None:
            IDACyberForm.hook = ScreenEAHook()
            IDACyberForm.hook.hook()

        self.__clink__ = ida_kernwin.plgform_new()
        self.title = None
        self.filterlist = self._load_filters()
        self.pw = None
        self.windowidx = 0
                
    def _update_status_text(self):
        self.status.setText('Adress %Xh | Cursor %Xh | Zoom %d | Width %d | Bytes %d' % (
            self.pw.get_address(),
            self.pw.get_cursor_address(),
            self.pw.get_zoom(),
            self.pw.get_width(),
            self.pw.get_bytes_total()))

    def _load_filters(self):
        filterdir = idadir('plugins/cyber')
        sys.path.append(filterdir)
        filters = []
        for entry in os.listdir(filterdir):
            if entry.lower().endswith('.py') and entry.lower() != '__init__.py':
                mod = os.path.splitext(entry)[0]
                filter = __import__(mod, globals(), locals(), [], 0)
                if filter.FILTER_INIT():
                    filters.append((filter, filter.FILTER_ENTRY()))
        return filters

    def _unload_filters(self):
        for filter, obj in self.filterlist:
            filter.FILTER_EXIT()

    def _change_screen_ea(self):
        if self.pw.get_sync_state():
            ea = ScreenEA()
            self.pw.set_addr(ea)
            # TODO
            self._update_status_text()

    def _select_filter(self, idx):
        self.pw.set_filter(self.filterlist[idx][1], idx)
        self.pw.repaint()

    def _toggle_sync(self, state):
        self.pw.set_sync_state(state == Qt.Checked)

    def Show(self, caption, options):
        i = 0
        while True:
            i += 1
            if i not in IDACyberForm.windows:
                title = 'IDACyber [%d]' % i
                caption = title
                IDACyberForm.windows.append(i)
                self.windowidx = i
                break        
        return ida_kernwin.plgform_show(self.__clink__, self, caption, options)
    
    def OnCreate(self, form):
        self.form = form
        self.parent = self.FormToPyQtWidget(form)

        vl = QtWidgets.QVBoxLayout()
        hl = QtWidgets.QHBoxLayout()
        hl2 = QtWidgets.QHBoxLayout()
        hl3 = QtWidgets.QHBoxLayout()
        hl4 = QtWidgets.QHBoxLayout()
        
        self.pw = PixelWidget(self.parent, IDACyberForm.idbh)
        self.pw.setFocusPolicy(Qt.StrongFocus | Qt.WheelFocus)
        self.pw.statechanged.connect(self._update_status_text)
        self.pw.set_filter(self.filterlist[0][1], 0)
        self.pw.set_addr(ScreenEA())

        vl.addWidget(self.pw)

        flt = QLabel()  
        flt.setText('Filter:')
        hl.addWidget(flt)

        self.filterChoser = QComboBox()
        self.filterChoser.addItems([obj.name for filter, obj in self.filterlist])
        self.filterChoser.currentIndexChanged.connect(self._select_filter)
        hl.addWidget(self.filterChoser)
        hl.addStretch(1)

        self.cb = QCheckBox('Sync')
        self.cb.setChecked(True)
        self.cb.stateChanged.connect(self._toggle_sync)
        hl2.addWidget(self.cb)

        self.status = QLabel()
        self.status.setText('Cyber, cyber!')
        hl4.addWidget(self.status)

        vl.addLayout(hl)
        vl.addLayout(hl2)
        vl.addLayout(hl3)
        vl.addLayout(hl4)

        self.parent.setLayout(vl)
        if IDACyberForm.hook is not None:
                IDACyberForm.hook.new_ea.connect(self._change_screen_ea)

    def OnClose(self, options):
        options = PluginForm.FORM_SAVE | PluginForm.FORM_NO_CONTEXT
        IDACyberForm.windows.remove(self.windowidx)
        self._unload_filters()
        if not len(IDACyberForm.windows):
            IDACyberForm.hook.unhook()
            IDACyberForm.hook = None

# -----------------------------------------------------------------------

class IDACyberPlugin(plugin_t):
    flags = 0
    comment = ''
    help = ''
    wanted_name = 'IDACyber'
    wanted_hotkey = 'Ctrl-Shift-C'

    def init(self):
        global banner
        msg("%s" % banner)
        return PLUGIN_KEEP

    def run(self, arg):
        form = IDACyberForm()
        form.Show(None, options = PluginForm.FORM_MENU|PluginForm.FORM_RESTORE|PluginForm.FORM_PERSIST)

    def term(self):
        pass

# -----------------------------------------------------------------------

def PLUGIN_ENTRY():   
    return IDACyberPlugin()
