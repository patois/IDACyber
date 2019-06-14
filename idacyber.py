import os
import sys

import ida_kernwin
import ida_diskio
import ida_bytes
import ida_segment
import ida_idaapi
import ida_nalt
import ida_idp

from PyQt5.QtWidgets import (QWidget, QApplication, QCheckBox, QLabel,
    QComboBox, QSizePolicy, QVBoxLayout, QHBoxLayout)
from PyQt5.QtGui import (QPainter, QColor, QFont, QPen,
    QPixmap, QImage, qRgb, QPainterPath, QStaticText)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QRect, QSize, QPoint


__author__ = 'Dennis Elser'

BANNER = """
.___ .______  .______  ._______ ____   ____._______ ._______.______  
: __|:_ _   \ :      \ :_.  ___\\   \_/   /: __   / : .____/: __   \ 
| : ||   |   ||   .   ||  : |/\  \___ ___/ |  |>  \ | : _/\ |  \____|
|   || . |   ||   :   ||    /  \   |   |   |  |>   \|   /  \|   :  \ 
|   ||. ____/ |___|   ||. _____/   |___|   |_______/|_.: __/|   |___\ 
|___| :/          |___| :/                             :/   |___|
"""

PLUGIN_HELP = """
IDACyber Quick Manual
====================================================================

Controls:
====================================================================

  Mouse controls:
  ---------------
* Click + drag            - Pan graph vertically
* Click + SHIFT + drag    - Pan graph horizontally
* Wheel                   - Pan graph vertically
* Wheel + SHIFT           - Pan graph horizontally
* Wheel + CTRL            - Zoom
* Wheel + h               - Change width (in 8th steps)
* Click + drag + h        - Change width (in 8th steps)
* Wheel + x               - Change width (one step)
* Click + drag + x        - Change width (one step)
* Double click            - Jump to address under cursor

  Keyboard controls:
  ------------------
* CTRL-F1                 - Display this help/quick manual
* F2                      - Display help for current filter
* F12                     - Export current graph to disk

* UP                      - Pan up
* DOWN                    - Pan down
* UP + SHIFT              - Pan up (one step)
* DOWN + SHIFT            - Pan down (one step)
* PAGE UP                 - Pan up a 'page'
* PAGE DOWN               - Pan down a 'page'
* CTRL-PLUS               - Zoom in
* CTRL-MINUS              - Zoom out
* B                       - Select previous filter
* N                       - Select next filter
* G                       - Go to address (accepts expressions)
* S                       - Toggle 'sync' setting
* D                       - Switch between hex/ascii
* T                       - Turn hex/ascii dump on/off


Check out the official project site for updates:

https://github.com/patois/IDACyber

"""


#   TODO:
#   * refactor
#   * colorfilter: improve arrows/pointers
#   * optimizations
#   * load filters using "require"
#   * add grid?
#   * use builtin Qt routines for scaling etc?
#   * store current settings in netnode?
#   * review signal handlers
#   * implement feature that generates a graph of all memory content/current
#     idb using the current color filter which is then saved/exported to disk
#   * implement color filter: dbghook, memory read/write tracing
#   * implement color filter: apply recorded trace log to graph
#   * implement color filter: colorize instructions/instruction groups
#   * implement color filter: Entropy visualization
#   * fix Hubert (beatcounter functionality, frame adjustment)
#   * draggable slider/scrollbar?

# I believe this is Windows-only?
FONT_DEFAULT = "Consolas"
HL_COLOR = 0x0037CC
HIGHLIGHTED_ITEM = None

class ColorFilter():
    """every new color filters must inherit this class"""
    name = None
    highlight_cursor = True
    help = None
    width = 16
    sync = True
    lock_width = False
    lock_sync = False
    show_address_range = True
    zoom = 10
    link_pixel = True
    support_selection = False
    disable_data = False


    def __init__(self, pw=None):
        pass

    """called when filter is selected in list"""
    def on_activate(self, idx):
        pass

    """called on deselection of filter (or when plugin closes)"""
    def on_deactivate(self):
        pass

    """handles mouse click events"""
    def on_mb_click(self, event, addr, size, mouse_offs):
        pass
    
    """called whenever a new frame is about to be drawn"""
    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        return []

    """called before tooltip is shown"""
    def on_get_tooltip(self, addr, size, mouse_offs):
        return None

    """called after on_process_buffer
    returns annotations and arrows/pointers"""
    def on_get_annotations(self, addr, size, mouse_offs):
        return None

# -----------------------------------------------------------------------
def is_ida_version(requested):
    rv = requested.split(".")
    kv = ida_kernwin.get_kernel_version().split(".")

    count = min(len(rv), len(kv))
    if not count:
        return False

    for i in xrange(count):
        if int(kv[i]) < int(rv[i]):
            return False
    return True

# -----------------------------------------------------------------------
def highlight_item(ea):
    global HIGHLIGHTED_ITEM

    unhighlight_item()
    
    current_color = ida_nalt.get_item_color(ea)
    HIGHLIGHTED_ITEM = (ea, current_color)
    ida_nalt.set_item_color(ea, HL_COLOR)

# -----------------------------------------------------------------------
def unhighlight_item():
    global HIGHLIGHTED_ITEM

    if HIGHLIGHTED_ITEM:
        ida_nalt.set_item_color(HIGHLIGHTED_ITEM[0], HIGHLIGHTED_ITEM[1])
        HIGHLIGHTED_ITEM = None

# -----------------------------------------------------------------------
class ScreenEAHook(ida_kernwin.View_Hooks):
    def __init__(self):
        ida_kernwin.View_Hooks.__init__(self)
        self.sh = SignalHandler()
        self.new_ea = self.sh.ida_newea
    
    def view_loc_changed(self, widget, curloc, prevloc):
        if curloc is not prevloc:
            self.new_ea.emit()

# -----------------------------------------------------------------------
class SignalHandler(QObject):    
    pw_statechanged = pyqtSignal()
    pw_next_filter = pyqtSignal()
    pw_prev_filter = pyqtSignal()
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

        result = ida_bytes.get_bytes_and_mask(ea, count)
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
        base = ida_idaapi.BADADDR
        qty = ida_segment.get_segm_qty()
        for i in xrange(qty):
            seg = ida_segment.getnseg(i)
            if seg and seg.contains(ea):
                base = seg.startEA
                break
        return base

# -----------------------------------------------------------------------
class PixelWidget(QWidget):
    def __init__(self, form, bufhandler):
        super(PixelWidget, self).__init__()

        self.form = form
        self.set_zoom(10)
        self.maxPixelsPerLine = 64
        self.maxPixelsTotal = 0
        self.prev_mouse_y = 0
        self.key = None
        self.buffers = None
        self.offs = 0
        self.base = 0
        self.fm = None
        self.filter_idx = 0
        self.mouseOffs = 0
        self.sync = True
        self.bh = bufhandler
        self.mouse_abs_x = 0
        self.mouse_abs_y = 0
        self.elemX = 0
        self.elemY = 0
        self.rect_x = 0
        self.rect_x_width = 0
        self.lock_width = False
        self.lock_sync = False
        self.link_pixel = True
        self.highlight_cursor = False
        self.render_data = True
        self.cur_formatter_idx = 0
        self.max_formatters = 2

        self.setMouseTracking(True)        
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.sh = SignalHandler()
        self.statechanged = self.sh.pw_statechanged
        self.next_filter = self.sh.pw_next_filter
        self.prev_filter = self.sh.pw_prev_filter

        self.qp = QPainter()
        
        self.show()

    def paintEvent(self, event):
        if not self.fm:
            return

        # set leftmost x-coordinate of graph
        zoom_level = self.get_zoom()        
        self.rect_x_width = self.get_width() * zoom_level       
        self.rect_x = (self.rect().width() / 2) - (self.rect_x_width / 2)

        self.qp.begin(self)

        # what is a good default font for OSX/Linux?
        self.qp.setFont(QFont(FONT_DEFAULT))

        # fill background
        self.qp.fillRect(self.rect(), Qt.black)

        content_addr = content_size = None
        if self.fm.support_selection:
            selected, start, end = ida_kernwin.read_range_selection(None)
            if selected:
                content_addr = start#min(start, end)
                content_size = end - start#max(start, end) - content_addr

        # use colorfilter to render image
        img = self.render_image(addr=content_addr, buf_size=content_size)

        if img:
            """
            if zoom_level > 6:
                opacity = self.qp.opacity()
                full_opacity_zoom = 40.0
                cur_opacity = (1.0 - (full_opacity_zoom - float(min(zoom_level-1, full_opacity_zoom)))/full_opacity_zoom)
                self.qp.setOpacity(1.0-cur_opacity)
            """
            # draw image
            self.qp.drawImage(QRect(QPoint(self.rect_x, 0), 
                QPoint(self.rect_x + self.get_width() * zoom_level, (self.get_pixels_total() / self.get_width()) * zoom_level)),
                img)

            # TODO: pen color contrast
            # TODO: data export: render data
            # TODO: default fonts / OS?
            # TODO: optimization
            # FIXME: there's a bug with gaps/unmapped buffers
            if self.render_data and not self.fm.disable_data and zoom_level > 6:
                self.qp.setPen(QColor(Qt.white))
                fontsize = self.qp.font().pointSize()
                font = self.qp.font()

                font.setPointSize(zoom_level/3)
                self.qp.setFont(font)
                
                opacity = self.qp.opacity()
                full_opacity_zoom = 28
                cur_opacity = (1.0 - (full_opacity_zoom - float(min(zoom_level-1, full_opacity_zoom)))/full_opacity_zoom)
                self.qp.setOpacity(cur_opacity)
                
                m = self.qp.fontMetrics()
                x = y = 0
                num_pixels_per_row = self.get_width()

                if self.cur_formatter_idx == 0:
                    sample = "%c" % (ord('X'))
                    cwidth = m.width(sample)
                    cheight = m.height()

                    for mapped, buf in self.buffers:
                        for i in range(len(buf)):
                            if mapped:
                                b = ord(buf[i])
                                data = "%c" % (chr(b) if b in range(0x20, 0x7E) else ".")

                                self.qp.drawStaticText(
                                    self.rect_x + x*zoom_level + (zoom_level - cwidth)/2,
                                    y*zoom_level + (zoom_level - cheight)/2,
                                    QStaticText(data))

                            x = (i + 1) % num_pixels_per_row
                            if not x:
                                y = y + 1

                elif self.cur_formatter_idx == 1:
                    sample = "%02X" % (ord('X'))
                    cwidth = m.width(sample)
                    cheight = m.height()

                    for mapped, buf in self.buffers:
                        for i in range(len(buf)):
                            if mapped:
                                data = "%02X" % ord(buf[i])                                

                                self.qp.drawStaticText(
                                    self.rect_x + x*zoom_level + (zoom_level - cwidth)/2,
                                    y*zoom_level + (zoom_level - cheight)/2,
                                    QStaticText(data))

                            x = (i + 1) % num_pixels_per_row
                            if not x:
                                y = y + 1


                self.qp.setOpacity(opacity)
                font.setPointSize(fontsize)
                self.qp.setFont(font)

        if self.show_address_range and self.fm.link_pixel:
            self.render_slider(addr=content_addr, buf_size=content_size)

        # get and draw annotations and pointers
        annotations = self.fm.on_get_annotations(content_addr if content_addr else self.get_address(),
            self.get_pixels_total(),
            self.mouseOffs)

        if annotations:
            self.render_annotations(annotations)

        self.qp.end()
        return

    def render_slider(self, addr=None, buf_size=None):
        if addr is None or buf_size is None:
            addr = self.base + self.offs
            buf_size = self.get_pixels_total()

        lowest_ea = ida_idaapi.get_inf_structure().get_minEA()
        highest_ea = ida_idaapi.get_inf_structure().get_maxEA()
        start_offs = addr - lowest_ea
        addr_space = highest_ea - lowest_ea

        perc_s = float(start_offs) / float(addr_space)
        perc_e = float(start_offs+buf_size) / float(addr_space)
        
        bar_width = 20

        spaces_bar = 5
        bar_x = self.rect_x - spaces_bar - bar_width
        bar_y = 5
        bar_height = self.rect().height() - 2 * bar_y
        self.qp.fillRect(bar_x, bar_y, bar_width, bar_height, QColor(0x191919))

        slider_offs_s = int(round(perc_s * bar_height))
        slider_offs_e = int(round(perc_e * bar_height))

        spaces_slider = 1
        slider_x = bar_x + spaces_slider
        slider_y = bar_y + slider_offs_s
        slider_width = bar_width - 2 * spaces_slider
        # limit slider height to bar_height
        slider_height = max(min(slider_offs_e - slider_offs_s, bar_height - (slider_y - bar_y)), 4)

        self.qp.fillRect(slider_x, slider_y, slider_width, slider_height, QColor(0x404040))

        # draw addresses
        top = '%X:' % self.get_address()
        bottom = '%X' % (self.get_address() + ((self.get_pixels_total() / self.get_width()) - 1) * self.get_width())
        self.qp.setPen(QColor(0x808080))
        self.qp.drawText(self.rect_x - self.qp.fontMetrics().width(top) - bar_width - 2 * spaces_bar,
            self.qp.fontMetrics().height(),
            top)
        self.qp.drawText(self.rect_x - self.qp.fontMetrics().width(bottom) - bar_width - 2 * spaces_bar,
            self.rect().height() - self.qp.fontMetrics().height() / 2,
            bottom)
        return

    def render_image(self, addr=None, buf_size=None, cursor=True):
        size = self.size()
        self.maxPixelsTotal = self.get_width() * (size.height() / self.pixelSize)
        if addr is None or buf_size is None:
            addr = self.base + self.offs
            buf_size = self.get_pixels_total()

        self.buffers = self.bh.get_buffers(addr, buf_size)
        img = QImage(self.get_width(), size.height() / self.pixelSize, QImage.Format_RGB32)
        pixels = self.fm.on_process_buffer(self.buffers, addr, self.get_pixels_total(), self.mouseOffs)

        x = y = 0
        # transparency effect for unmapped bytes
        transparency_dark = [qRgb(0x2F,0x4F,0x4F), qRgb(0x00,0x00,0x00)]
        transparency_err = [qRgb(0x7F,0x00,0x00), qRgb(0x33,0x00,0x00)]
        for mapped, pix in pixels:
            if not mapped:
                if pix is None:
                    pix = transparency_dark[(x&2 != 0) ^ (y&2 != 0)]
            img.setPixel(x, y, pix)

            x = (x + 1) % self.get_width()
            if not x:
                y = y + 1

        if len(pixels) != self.get_pixels_total():
            for i in xrange(self.get_pixels_total() - len(pixels)):
                pix = transparency_err[(x&2 != 0) ^ (y&2 != 0)]
                img.setPixel(x, y, pix)
                x = (x + 1) % self.get_width()
                if not x:
                    y = y + 1

        if ((cursor and self.fm.highlight_cursor) and
            self.mouse_abs_x >= self.rect_x and
            self.mouse_abs_x < self.rect_x + self.rect_x_width):
            
            coords = self.get_coords_by_address(self.get_cursor_address())
            if coords:
                x,y = coords
            else:
                x = self.get_elem_x()
                y = self.get_elem_y()
            p = QPoint(x, y)
            img.setPixel(p, ~(img.pixelColor(p)).rgb())

        return img

    def render_annotations(self, annotations=[]):
        a_offs = 20
        base_x = self.rect_x + self.get_width() * self.pixelSize + a_offs + 10
        base_y = self.qp.fontMetrics().height()
        offs_x = 5
        offs_y = base_y

        for coords, arr_color, ann, txt_color in annotations:
            # draw arrow (experimental / WIP)
            self.qp.setPen(QColor(Qt.white if txt_color is None else txt_color))
            self.qp.drawText(base_x+10, (base_y+offs_y)/2, ann)
            target_x = target_y = None

            if coords:
                if isinstance(coords, tuple):
                    target_x, target_y = coords
                else:
                    ptr = self.get_coords_by_address(coords)
                    if ptr:
                        target_x, target_y = ptr

                if target_x is not None and target_y is not None:
                    target_x *= self.get_zoom()
                    target_y *= self.get_zoom()

                    self.qp.setPen(QColor(Qt.white if arr_color is None else arr_color))
                    path = QPainterPath()
                    path.moveTo(base_x+offs_x, (base_y+offs_y)/2-base_y/2)

                    path.lineTo(base_x+offs_x - 4 - a_offs, (base_y+offs_y)/2-base_y/2)  # left
                    path.lineTo(base_x+offs_x - 4 - a_offs, ((target_y/10)*9) + self.get_zoom()/2) # down
                    path.lineTo(self.rect_x + target_x + self.get_zoom() / 2, ((target_y/10)*9) + self.get_zoom()/2) # left
                    path.lineTo(self.rect_x + target_x + self.get_zoom() / 2, target_y + self.get_zoom()/2) # down
                    a_offs = max(a_offs-2, 0)
                    self.qp.drawPath(path)
                else:
                    if not isinstance(coords, tuple):
                        direction = self.get_target_direction(coords)
                        if direction:
                            self.qp.setPen(QColor(Qt.white if arr_color is None else arr_color))
                            m = self.qp.fontMetrics()
                            dirhint = ['', '<<', '>>'][direction]
                            cwidth = m.width("%s" % (dirhint))
                            self.qp.drawText(base_x - cwidth, (base_y+offs_y)/2, dirhint)

            offs_y += 2*base_y + 5
        return

    # functions that can be called by filters
    # must no be called from within on_process_buffer()
    def on_filter_request_update(self, ea=None, center=True):
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

    def on_filter_update_zoom(self, zoom):
        self.set_zoom(zoom)
        return

    def on_filter_update_zoom_delta(self, delta):
        self.set_zoom_delta(delta)
        return
    # end of functions that can be called by filters

    def show_help(self):
        ida_kernwin.info("%s" % PLUGIN_HELP)

    def keyPressEvent(self, event):
        if self.key is None:
            self.key = event.key()
        return

    def keyReleaseEvent(self, event):
        update = False
        key = event.key()
        modifiers = event.modifiers()

        shift_pressed = ((modifiers & Qt.ShiftModifier) == Qt.ShiftModifier)
        ctrl_pressed = ((modifiers & Qt.ControlModifier) == Qt.ControlModifier)

        if key == Qt.Key_F1 and ctrl_pressed:
            self.show_help()

        elif key == Qt.Key_G:
            addr = ask_addr(self.base + self.offs, 'Jump to address')
            if addr is not None:
                if self.sync:
                    ida_kernwin.jumpto(addr)
                else:
                    minea = ida_idaapi.get_inf_structure().get_minEA()
                    maxea = ida_idaapi.get_inf_structure().get_maxEA()
                    dst = min(max(addr, minea), maxea)
                    self.set_addr(dst)

        elif key == Qt.Key_S:
            if not self.fm.lock_sync:
                self.set_sync_state(not self.get_sync_state())
                update = True

        elif key == Qt.Key_T:
            self.render_data = not self.render_data
            self.repaint()

        elif key == Qt.Key_D:
            self.cur_formatter_idx = (self.cur_formatter_idx + 1) % self.max_formatters
            self.repaint()

        elif key == Qt.Key_N:
            self.next_filter.emit()

        elif key == Qt.Key_B:
            self.prev_filter.emit()

        elif key == Qt.Key_F2:
            hlp = self.fm.help
            if hlp is None:
                hlp = 'Help unavailable'
            ida_kernwin.info('%s\n\n' % hlp)

        elif key == Qt.Key_F12:
            img = self.render_image(cursor = False)
            img = img.scaled(img.width()*self.pixelSize, img.height()*self.pixelSize, Qt.KeepAspectRatio, Qt.FastTransformation)
            done = False
            i = 0
            while not done:
                fname = 'IDACyber_%04d.bmp' % i
                if not os.path.isfile(fname):
                    if img.save(fname):
                        ida_kernwin.msg('File exported to %s\n' % fname)
                    else:
                        ida_kernwin.warning('Error exporting screenshot to %s.' % fname)
                    done = True
                i += 1
                if i > 40:
                    ida_kernwin.warning('Aborted. Error exporting screenshot.')
                    break

        elif key == Qt.Key_PageDown:
            self.set_offset_delta(-self.get_pixels_total())
            update = True

        elif key == Qt.Key_PageUp:
            self.set_offset_delta(self.get_pixels_total())
            update = True

        elif key == Qt.Key_Down:
            if shift_pressed:
                self.set_offset_delta(-1)
            else:
                self.set_offset_delta(-self.get_width())
            update = True

        elif key == Qt.Key_Up:
            if shift_pressed:
                self.set_offset_delta(1)
            else:
                self.set_offset_delta(self.get_width())
            update = True

        elif key == Qt.Key_Plus:
            if ctrl_pressed:
                self.set_zoom_delta(1)
            update = True

        elif key == Qt.Key_Minus:
            if ctrl_pressed:
                self.set_zoom_delta(-1)
            update = True

        self.key = None

        if update:
            if self.get_sync_state():
                ida_kernwin.jumpto(self.base + self.offs)
                self.activateWindow()
                self.setFocus()
            self.statechanged.emit()
            self.repaint()

        return

    def mouseReleaseEvent(self, event):
        self.prev_mouse_y = event.pos().y()
        self.fm.on_mb_click(event, self.get_address(), self.get_pixels_total(), self.mouseOffs)
        
        if self.get_sync_state():
            ida_kernwin.jumpto(self.base + self.offs)
            self.activateWindow()
            self.setFocus()
            self.statechanged.emit()
        return

    def mouseDoubleClickEvent(self, event):
        if self.link_pixel and event.button() == Qt.LeftButton:
            addr = self.base + self.offs + self._get_offs_by_pos(event.pos())
            ida_kernwin.jumpto(addr)
        return

    def wheelEvent(self, event):
        delta = event.angleDelta().y()/120

        # zoom
        if self.key == Qt.Key_Control:
            self.set_zoom_delta(delta)

        # width            
        elif self.key == Qt.Key_X:
            if not self.lock_width:
                self.set_width_delta(delta)

        # offset (fine)
        elif self.key == Qt.Key_Shift:
            self.set_offset_delta(delta)

            if self.get_sync_state():
                ida_kernwin.jumpto(self.base + self.offs)
                self.activateWindow()
                self.setFocus()

        elif self.key == Qt.Key_H:
            if not self.lock_width:
                less = delta < 0
                w = -8 if less else 8
                self.set_width((self.get_width() & 0xFFFFFFF8) + w)

        # offset (coarse)
        else:
            self.set_offset_delta(delta * self.get_width())
            
            if self.get_sync_state():
                ida_kernwin.jumpto(self.base + self.offs)
                self.activateWindow()
                self.setFocus()

        self.statechanged.emit()
        self.repaint()
        return
        
    def mouseMoveEvent(self, event):
        x = event.pos().x()
        y = event.pos().y()
        within_graph = (x >= self.rect_x and x < self.rect_x + self.rect_x_width)
        
        if within_graph:
            if event.buttons() == Qt.NoButton:
                self._update_mouse_coords(event.pos())
                self.mouseOffs = self._get_offs_by_pos(event.pos())
                
                if self.link_pixel and self.highlight_cursor:
                    highlight_item(ida_bytes.get_item_head(self.get_cursor_address()))
                elif self.highlight_cursor:
                    unhighlight_item()

                self.setToolTip(self.fm.on_get_tooltip(self.get_address(), self.get_pixels_total(), self.mouseOffs))

            # zoom
            elif self.key == Qt.Key_Control:
                self.set_zoom_delta(-1 if y > self.prev_mouse_y else 1)

            # width
            elif self.key == Qt.Key_X:
                if not self.lock_width:
                    self.set_width_delta(-1 if y > self.prev_mouse_y else 1)

            elif self.key == Qt.Key_H:
                if not self.lock_width:
                    less = y > self.prev_mouse_y
                    delta = -16 if less else 16
                    self.set_width((self.get_width() & 0xFFFFFFF0) + delta)

            # scrolling (offset)
            elif y != self.prev_mouse_y:
                # offset (fine)
                delta = y - self.prev_mouse_y

                # offset (coarse)
                if self.key != Qt.Key_Shift:
                    delta *= self.get_width()
                    
                self.set_offset_delta(delta)

            self.prev_mouse_y = y
            self.x = x
            self.statechanged.emit()
            self.repaint()
        return

    def set_sync_state(self, sync):
        self.sync = sync

    def get_sync_state(self):
        return self.sync

    def get_filter_idx(self):
        return self.filter_idx
    
    def set_filter(self, fltobj, idx):
        if self.fm:
            self.fm.on_deactivate()
        if fltobj:
            self.fm = fltobj

            """load filter config"""
            self.set_sync_state(self.fm.sync)
            self.lock_width = self.fm.lock_width
            self.set_width(self.fm.width)
            self.lock_sync = self.fm.lock_sync
            self.show_address_range = self.fm.show_address_range
            # disabled for now
            # self.set_zoom(self.fm.zoom)
            self.link_pixel = self.fm.link_pixel
            self.highlight_cursor = self.fm.highlight_cursor
            self.statechanged.emit()
            """load filter config end"""

            self.fm.on_activate(idx)
            self.filter_idx = idx
            unhighlight_item()
            self.repaint()

    def set_addr(self, ea, new_cursor=None):
        base = self.bh.get_base(ea)

        self._set_base(base)
        self._set_offs(ea - base)

        if new_cursor:
            self.set_cursor_address(new_cursor)
            if self.highlight_cursor:
                highlight_item(ea)

        self.repaint()

    def get_zoom(self):
        return self.pixelSize

    def set_zoom(self, zoom):
        self.pixelSize = zoom

    def set_zoom_delta(self, dzoom):
        self.set_zoom(max(1, self.pixelSize + dzoom))
        return

    def get_width(self):
        return self.maxPixelsPerLine

    def get_pixels_total(self):
        return self.maxPixelsTotal

    def get_address(self):
        return self.base + self.offs

    def get_cursor_address(self):
        return self.get_address() + self.mouseOffs

    def set_cursor_address(self, ea):
        self.mouseOffs = ea - self.get_address()

    def get_coords_by_address(self, address):
        base = self.get_address()
        # if address is visible in current window
        if address >= base and address < base + self.get_pixels_total():
            offs = address - base
            x = offs % self.get_width()
            y = offs / (self.get_width())
            return (x, y)
        return None

    def get_target_direction(self, address):
        base = self.get_address()
        # if address is visible in current window
        direction = None
        if address >= base and address < base + self.get_pixels_total():
            direction = 0
        elif address < base:
            direction = 1
        else:
            direction = 2
        return direction

    def set_width(self, width):
        self.maxPixelsPerLine = max(1, width)

    def set_width_delta(self, dwidth):
        self.maxPixelsPerLine = max(1, self.maxPixelsPerLine + dwidth)

    def set_offset_delta(self, doffs):
        newea = self.base + self.offs - doffs
        minea = ida_idaapi.get_inf_structure().get_minEA()
        maxea = ida_idaapi.get_inf_structure().get_maxEA()
        if doffs < 0:
            delta = doffs if newea < maxea else doffs - (maxea - newea)
        else:
            delta = doffs if newea >= minea else doffs - (minea - newea)
        self._set_offs(self.offs - delta)

    def _get_offs_by_pos(self, pos):
        elemX = self.get_elem_x()
        elemY = self.get_elem_y()
        offs = elemY * self.get_width() + elemX
        return offs

    def _update_mouse_coords(self, pos):
        x = pos.x()
        y = pos.y()
        self.mouse_abs_x = x
        self.mouse_abs_y = y

        self.elemX = max(0, min((max(0, x - self.rect_x)) / self.pixelSize, self.get_width() - 1))
        self.elemY = min(y / self.pixelSize, self.maxPixelsTotal / self.get_width() - 1)

    def get_elem_x(self):
        return self.elemX

    def get_elem_y(self):
        return self.elemY

    def _set_offs(self, offs):
        self.offs = offs

    def _set_base(self, ea):
        self.base = ea

# -----------------------------------------------------------------------
class IDACyberForm(ida_kernwin.PluginForm):
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
        self.filterlist = None
        self.pw = None
        self.windowidx = 0
        self.filterChoser = None
        self.cb = None
        self.status = None
        self.pw = None
        self.parent = None
        self.form = None
        self.clean_init = False

    def _update_widget(self):
        lbl_address = 'Address '
        lbl_cursor = 'Cursor '
        lbl_zoom = 'Zoom '
        lbl_pixel = 'Pixels '
        
        if self.pw.link_pixel:
            val_address = '%Xh' % self.pw.get_address()
            val_cursor = '%Xh' % self.pw.get_cursor_address()
        else:
            val_address = val_cursor = 'N/A'
        width = self.pw.get_width()
        val_zoom = '%d:1 ' % self.pw.get_zoom()
        val_pixel = '%dx%d ' % (width, self.pw.get_pixels_total()/width)

        status_text = ' | '.join((lbl_address + val_address,
            lbl_cursor + val_cursor,
            lbl_pixel + val_pixel,
            lbl_zoom + val_zoom))
        # TODO: move code to separate, new signal handler
        self.cb.setChecked(self.pw.sync)
        self.cb.setEnabled(not self.pw.lock_sync)
        self.status.setText(status_text)

    def _load_filters(self, pw):
        filters = []
        filterdir = os.path.join(ida_diskio.idadir('plugins'), 'cyber')
        if not os.path.exists(filterdir):
            usr_plugins_dir = os.path.join(ida_diskio.get_user_idadir(), "plugins")
            filterdir = os.path.join(usr_plugins_dir, 'cyber')
        if os.path.exists(filterdir):
            sys.path.append(filterdir)
            for entry in os.listdir(filterdir):
                if entry.lower().endswith('.py') and entry.lower() != '__init__.py':
                    mod = os.path.splitext(entry)[0]
                    fmod = __import__(mod, globals(), locals(), [], 0)
                    if fmod is not None:
                        flt = fmod.FILTER_INIT(pw)
                        if flt is not None:
                            filters.append((fmod, flt))
        return filters

    def _unload_filters(self):
        for fmod, obj in self.filterlist:
            obj.on_deactivate()
            fmod.FILTER_EXIT()

    def _change_screen_ea(self):
        if self.pw.get_sync_state():
            ea = ida_kernwin.get_screen_ea()
            self.pw.set_addr(ea, new_cursor=ea)
            # TODO
            self._update_widget()

    def _select_filter(self, idx):
        self.pw.set_filter(self.filterlist[idx][1], idx)
        self.pw.repaint()

    def _select_next_filter(self):
        next_idx = (self.pw.get_filter_idx() + 1) % len(self.filterlist)
        self.filterChoser.setCurrentIndex(next_idx)

    def _select_prev_filter(self):
        prev_idx = self.pw.get_filter_idx() - 1
        if prev_idx < 0:
            prev_idx = len(self.filterlist) - 1
        self.filterChoser.setCurrentIndex(prev_idx)

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

    def OnClose(self, options):
        if self.clean_init and IDACyberForm.hook is not None:
                IDACyberForm.hook.new_ea.disconnect(self._change_screen_ea)

        IDACyberForm.windows.remove(self.windowidx)
        self._unload_filters()
        unhighlight_item()

        # once all idacyber forms are closed
        if not len(IDACyberForm.windows):
            IDACyberForm.hook.unhook()
            IDACyberForm.hook = None

    def OnCreate(self, form):
        self.form = form
        self.parent = self.FormToPyQtWidget(form)

        vl = QVBoxLayout()
        hl = QHBoxLayout()
        hl2 = QHBoxLayout()
        hl3 = QHBoxLayout()
        hl4 = QHBoxLayout()

        flt = QLabel()  
        flt.setText('Filter:')
        hl.addWidget(flt)

        self.cb = QCheckBox('Sync')
        self.cb.setChecked(True)
        self.cb.stateChanged.connect(self._toggle_sync)
        hl2.addWidget(self.cb)

        self.status = QLabel()
        self.status.setText('Cyber, cyber!')
        hl4.addWidget(self.status)

        self.pw = PixelWidget(self.parent, IDACyberForm.idbh)
        self.pw.setFocusPolicy(Qt.StrongFocus | Qt.WheelFocus)

        self.pw.statechanged.connect(self._update_widget)
        self.pw.next_filter.connect(self._select_next_filter)
        self.pw.prev_filter.connect(self._select_prev_filter)

        self.filterlist = self._load_filters(self.pw)
        if not len(self.filterlist):
            ida_kernwin.warning("IDACyber: no filters found within /plugins/cyber/")
            return

        self.pw.set_filter(self.filterlist[0][1], 0)
        self.pw.set_addr(ida_kernwin.get_screen_ea())

        self.filterChoser = QComboBox()
        self.filterChoser.addItems([obj.name for filter, obj in self.filterlist])
        self.filterChoser.currentIndexChanged.connect(self._select_filter)
        hl.addWidget(self.filterChoser)
        hl.addStretch(1)

        vl.addWidget(self.pw)

        vl.addLayout(hl)
        vl.addLayout(hl2)
        vl.addLayout(hl3)
        vl.addLayout(hl4)

        self.parent.setLayout(vl)
        if IDACyberForm.hook is not None:
                IDACyberForm.hook.new_ea.connect(self._change_screen_ea)
        self.clean_init = True
        return

# -----------------------------------------------------------------------
class idb_hook_t(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    def savebase(self):
        unhighlight_item()
        return 0

# -----------------------------------------------------------------------
class IDACyberPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD
    comment = ''
    help = ''
    wanted_name = 'IDACyber'
    wanted_hotkey = 'Ctrl-Shift-C'

    def init(self):
        if not is_ida_version("7.0"):
            return ida_idaapi.PLUGIN_SKIP

        self.idbhook = idb_hook_t()
        self.idbhook.hook()

        self.forms = []
        self.options = (ida_kernwin.PluginForm.WOPN_MENU |
            ida_kernwin.PluginForm.WOPN_ONTOP |
            ida_kernwin.PluginForm.WOPN_RESTORE |
            ida_kernwin.PluginForm.FORM_SAVE |
            ida_kernwin.PluginForm.WOPN_PERSIST |
            ida_kernwin.PluginForm.WCLS_CLOSE_LATER)

        ida_kernwin.msg('%s\n+ %s loaded.\n+ %s opens a new instance.\n+ Ctrl-F1 for help.\n\n' % (
            BANNER,
            IDACyberPlugin.wanted_name,
            IDACyberPlugin.wanted_hotkey))

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        frm = IDACyberForm()
        frm.Show(None, options = self.options)
        self.forms.append(frm)

    def term(self):
        self.idbhook.unhook()
        # sloppy. windows might have been closed / memory free'd
        for frm in self.forms:
            if frm:
                frm.Close(options = self.options)

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return IDACyberPlugin()