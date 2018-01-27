from PyQt5.QtGui import qRgb, QColor
from idacyber import ColorFilter
from PyQt5.QtCore import Qt
from ida_dbg import get_ip_val, get_sp_val, DBG_Hooks, is_step_trace_enabled
from ida_bytes import get_item_size
from ida_kernwin import register_timer, unregister_timer, warning, ask_yn

HOOK = None
highlighted = True
maxhits = 100

class DbgHook(DBG_Hooks):
    def __init__(self):
        self.pw = None
        self.timer = None
        self.hits = {}
        self.counter = 0
        DBG_Hooks.__init__(self)

    def enable_timer(self):
        self.disable_timer()
        self.timer = register_timer(200, self.flash_cb)

    def disable_timer(self):
        if self.timer:
            unregister_timer(self.timer)
            self.timer = None

    def add_hit(self):
        global maxhits

        ip = get_ip_val()
        try:
            data = self.hits[ip]
            x = data[0]
            if x <= maxhits:
                data[0] = x + 1
        except KeyError:
            self.hits[ip] = [1, get_item_size(ip)]

    def set_pw(self, pw):
        self.pw = pw
        if not self.timer:
            self.enable_timer()

    def flash_cb(self):
        global highlighted
        if self.pw:
            self.pw.filter_request_update()
            highlighted = not highlighted
        # timer will unregister itself if it returns -1
        return 200

    def request_update_ip_view(self, ip=None):
        _ip = ip if ip else get_ip_val()
        if self.pw:
            self.pw.filter_request_update(_ip, center=True)

    """looks neat but tends to mess up something
    The current version of IDA v7.x seems to have
    bugs within the iplementation of the tracing
    feature / DBG_Hooks. Still, it could also be
    problem of this plugin, hard to tell right now"""
    def dbg_trace(self, tid, ip):
        self.add_hit()
        #if not self.counter % 1000:
        if True:
            self.counter = 0
            self.request_update_ip_view(ip)
        self.counter += 1
        return 0

    """
    def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        self.enable_timer()
        return 0
    """
    def dbg_process_exit(self, pid, tid, ea, exit_code):
        self.disable_timer()
        return 0
    """
    def dbg_process_attach(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        self.enable_timer()
        return 0
    """
    def dbg_process_detach(self, pid, tid, ea):
        self.disable_timer()
        return 0

    """apparently, this is sufficient for logging the IP
    since it is called along with the other events
    that have been commented out below"""
    def dbg_suspend_process(self):
        self.enable_timer()
        self.add_hit()
        self.request_update_ip_view()
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
    name = "Dbg"
    help = "Example for filter_request_update() events."
    highlight_cursor = False

    def __init__(self):
        self.pw = None
        self.palette = [0x1d59eb, 0x3466c0, 0x0ea7ac, 0x22b592, 0xebaf1d]

    def on_activate(self, idx, pw):
        global HOOK
        self.pw = pw
        if HOOK:
            HOOK.set_pw(self.pw)
        return

    def on_mb_click(self, button, addr, mouse_offs):
        if button == Qt.RightButton:
            if ask_yn(1, "Clear trace?") == 1:
                global HOOK
                HOOK.hits = {}
        return

    def byte2coloridx(self, c):
        return c/(0xff/(len(self.palette)-1))

    def get_annotations(self, address, size, mouse_offs):
        ann = []
        ip = get_ip_val()
        sp = get_sp_val()
        if ip is not None and sp is not None:
            ann.append((ip, Qt.red, "%X (IP)" % ip, Qt.red))
            ann.append((sp, Qt.green, "%X (SP)" % sp, Qt.green))
        return ann

    def render_img(self, buffers, addr, mouse_offs):
        colors = []
        goffs = 0
        global highlighted
        global HOOK
        global maxhits

        for mapped, buf in buffers:
            if mapped:
                ip = get_ip_val()
                i = 0
                while i < len(buf):
                    if highlighted and ip == addr + goffs + i:
                        size = get_item_size(ip)
                        for j in xrange(size):
                            colors.append((True, qRgb(0xFF, 0x45, 0)))
                        i += size
                        continue
                    else:
                        if addr + goffs + i in HOOK.hits:
                            data = HOOK.hits[addr + goffs + i]
                            size = data[1]
                            hits = data[0]
                            for j in xrange(size):
                                base = self.palette[len(self.palette)-1]
                                col = QColor(base).lighter(100+(float(hits)/maxhits)*100).rgb()
                                colors.append((True, col))
                            i += size
                            continue
                        else:                            
                            c = ord(buf[i])
                            colors.append((True, self.palette[self.byte2coloridx(c)]))
                    i += 1
            else:
                for i in xrange(len(buf)):
                    colors.append((False, None))
            goffs += len(buf)
        return colors

def FILTER_INIT():
    # how can we determine whether the currently loaded
    # processor module has got a debugger module?
    global HOOK
    HOOK = DbgHook()
    HOOK.hook()
    return True
    
def FILTER_ENTRY():
    return Dbg()

def FILTER_EXIT():
    global HOOK
    if HOOK:
        HOOK.unhook()
        HOOK = None
    return