from PyQt5.QtGui import qRgb, QColor
from idacyber import ColorFilter
from PyQt5.QtCore import Qt
from ida_dbg import get_ip_val, get_sp_val, DBG_Hooks, is_step_trace_enabled, is_debugger_on, get_process_state
from ida_bytes import get_item_size
from ida_kernwin import register_timer, unregister_timer, warning, ask_yn

class DbgHook(DBG_Hooks):
    def __init__(self, pw):
        self.pw = pw
        self.timer = None
        self.hits = {}
        self.counter = 0
        self.highlighted = True
        self.maxhits = 100
        self.enable_timer()
        DBG_Hooks.__init__(self)

    def enable_timer(self):
        self.disable_timer()
        self.timer = register_timer(200, self._flash_cb)
        return

    def disable_timer(self):
        if self.timer:
            unregister_timer(self.timer)
            self.timer = None
        return

    def _add_hit(self):
        ip = get_ip_val()
        try:
            data = self.hits[ip]
            x = data[0]
            if x <= self.maxhits:
                data[0] = x + 1
        except KeyError:
            self.hits[ip] = [1, get_item_size(ip)]

    def _flash_cb(self):
        if self.pw:
            # if debugger is running and process is suspended
            if is_debugger_on() and get_process_state() == -1:
                self.pw.on_filter_request_update()
                self.highlighted = not self.highlighted
        # timer will unregister itself if it returns -1
        return 200

    def _request_update_ip_view(self, ip=None):
        _ip = ip if ip else get_ip_val()
        if self.pw:
            self.pw.on_filter_request_update(_ip, center=True)

    """there is a bug which causes this callback to not be
    called if step tracing is enabled, then disabled, then
    enabled again - not sure if related to IDA or this plugin"""
    def dbg_trace(self, tid, ip):
        self._add_hit()

        #if not self.counter % 1000:
        if True:
            self.counter = 0
            self._request_update_ip_view(ip)
        self.counter += 1
        return 0

    """apparently, this is sufficient for logging the IP
    since it is called along with the other events
    that have been commented out below"""
    def dbg_suspend_process(self):
        self._add_hit()
        self._request_update_ip_view()
        return 0

    """
    def dbg_step_until_ret(self):
        self.add_hit()
        self.request_update_ip_view()
        return 0

    def dbg_run_to(self, pid, tid, ea):
        self.add_hit()
        self.request_update_ip_view()
        return 0

    def dbg_bpt(self, tid, bptea):
        self.add_hit()
        self.request_update_ip_view()
        return 0

    def dbg_step_into(self):
        self.add_hit()
        self.request_update_ip_view()
        return 0

    def dbg_step_over(self):
        self.add_hit()
        self.request_update_ip_view()
        return 0
    """

class Dbg(ColorFilter):
    name = "Debug"
    help = "Example for on_filter_request_update() events.\nCan be used with step-tracing enabled."
    highlight_cursor = False
    sync = False
    zoom = 5
    width = 32

    def __init__(self, pw):
        self.pw = pw
        self.palette = [0x1d59eb, 0x3466c0, 0x0ea7ac, 0x22b592, 0xebaf1d]
        self.exec_col = 0x59eb1d
        self.hook = None
        return

    def on_activate(self, idx):
        """if self.hook is not None:
            pass"""
        self.hook = DbgHook(self.pw)
        self.hook.hook()
        return

    def on_deactivate(self):
        if self.hook is not None:
            self.hook.disable_timer()
            self.hook.unhook()
            self.hook = None
        return

    def on_mb_click(self, event, addr, size, mouse_offs):
        if event.button() == Qt.RightButton:
            if ask_yn(1, "Clear trace?") == 1:
                self.hook.hits = {}
        return

    def _byte2coloridx(self, c):
        return c/(0xff/(len(self.palette)-2))

    def on_get_annotations(self, address, size, mouse_offs):
        ann = []
        ip = get_ip_val()
        sp = get_sp_val()
        if ip is not None and sp is not None:
            ann.append((ip, Qt.red, "%X (IP)" % ip, Qt.red))
            ann.append((sp, Qt.green, "%X (SP)" % sp, Qt.green))
        return ann

    def on_process_buffer(self, buffers, addr, size, mouse_offs):
        colors = []
        goffs = 0

        for mapped, buf in buffers:
            if mapped:
                ip = get_ip_val()
                i = 0
                while i < len(buf):
                    if self.hook.highlighted and ip == addr + goffs + i:
                        size = get_item_size(ip)
                        for j in xrange(size):
                            colors.append((True, qRgb(0xFF, 0x45, 0)))
                        i += size
                        continue
                    else:
                        if addr + goffs + i in self.hook.hits:
                            data = self.hook.hits[addr + goffs + i]
                            size = data[1]
                            hits = data[0]
                            for j in xrange(size):
                                base = self.palette[len(self.palette)-1]
                                col = QColor(base).darker(100+(float(hits)/self.hook.maxhits)*105).rgb()
                                colors.append((True, col))
                            i += size
                            continue
                        else:                            
                            c = ord(buf[i])
                            colors.append((True, self.palette[self._byte2coloridx(c)]))
                    i += 1
            else:
                for i in xrange(len(buf)):
                    colors.append((False, None))
            goffs += len(buf)
        return colors
    
def FILTER_INIT(pw):
    return Dbg(pw)

def FILTER_EXIT():
    return