from PyQt5.QtGui import qRgb, QColor
from idacyber import ColorFilter
from PyQt5.QtCore import Qt
from ida_idd import regval_t 
from ida_dbg import (get_reg_val, get_ip_val, get_sp_val,
    DBG_Hooks, is_step_trace_enabled,
    is_debugger_on, get_process_state)
from ida_bytes import get_item_size
from ida_kernwin import (register_timer, unregister_timer,
    warning, ask_yn, get_kernel_version)
from ida_funcs import get_func, get_func_name
from ida_frame import (frame_off_lvars, frame_off_savregs,
    frame_off_retaddr, get_frame, get_spd)
from ida_struct import (get_struc_name, get_member_name,
    get_struc_size)
from ida_idaapi import get_inf_structure

def get_ida_version():
    ver = get_kernel_version().split(".")
    major, minor = ver
    return ((int(major), int(minor)))

# workaround for IDA7.0
def is_ida70():
    major, minor = get_ida_version()
    return major == 7 and minor == 0

def _get_sp_val():
    inf = get_inf_structure()
    proc_name = inf.procName.lower()
    regname = ""
    if proc_name == "metapc":
        if inf.is_64bit():
            regname = "rsp"
        elif inf.is_32bit():
            regname = "esp"
        else:
            regname = "sp"
    elif proc_name == "arm":
        regname = "sp"
    rv = regval_t()
    if get_reg_val(regname, rv):
        return rv.ival
    return None

def _get_ip_val():
    inf = get_inf_structure()
    proc_name = inf.procName.lower()
    regname = ""
    if proc_name == "metapc":
        if inf.is_64bit():
            regname = "rip"
        elif inf.is_32bit():
            regname = "eip"
        else:
            regname = "ip"
    elif proc_name == "arm":
        regname = "pc"
    rv = regval_t()
    if get_reg_val(regname, rv):
        return rv.ival
    return None

get_sp_val = _get_sp_val if is_ida70() else get_sp_val
get_ip_val = _get_ip_val if is_ida70() else get_ip_val

class FrameInfo:
    def __init__(self):
        self.members = {}
        self.framesize = 0
        self.ea = 0
        self._get_frame()

    def _get_frame(self):
        result = False
        sp = get_sp_val()
        ip = get_ip_val()

        if ip and sp:
            f = get_func(ip)
            if f:
                frame = get_frame(f)
                if frame:
                    self.framesize = get_struc_size(frame)
                    n = frame.memqty
                    frame_offs = f.frregs + f.frsize
                    self.ea = sp - get_spd(f, ip) - frame_offs
                    for i in range(n):
                        m = frame.get_member(i)
                        if m:
                            lvar_name = get_member_name(m.id)
                            lvar_ea = self.ea + m.soff
                            lvar_size = m.eoff - m.soff
                            self.members[lvar_ea] = (lvar_name, m.soff, lvar_size, frame_offs)
                    result = True
        return result

    def get_element_boundaries(self, addr):
        for ea, data in self.members.items():
            name, offs, size, foffs = data
            if addr in range(ea, ea+size):
                return (ea, ea+size)
        return None

class DbgHook(DBG_Hooks):
    def __init__(self, pw):
        self.pw = pw
        self.timer = None
        self.highlighted = True
        self.enable_timer()
        DBG_Hooks.__init__(self)

    def enable_timer(self):
        self.disable_timer()
        self.timer = register_timer(300, self._flash_cb)
        return

    def disable_timer(self):
        if self.timer:
            unregister_timer(self.timer)
            self.timer = None
        return

    def _flash_cb(self):
        if self.pw:
            # if debugger is running and process is suspended
            if is_debugger_on() and get_process_state() == -1:
                self.pw.on_filter_request_update()
                self.highlighted = not self.highlighted
        return 300

    def _request_update_viewer(self, sp=None):
        _sp = sp if sp else get_sp_val()
        if self.pw:
            self.pw.on_filter_request_update(_sp, center=True)

    def dbg_suspend_process(self):
        self._request_update_viewer()
        return 0

class StackyMcStackface(ColorFilter):
    name = "Stacky McStackface"
    help = """This filter draws the current function's
stack frame during a debug session.

Controls:
Middle mouse button: cycle color palettes
Right mouse button: toggle arrow

Use IDACyber controls to navigate
through memory (Press F3 for help)
"""
    highlight_cursor = False
    sync = False
    lock_sync = True
    zoom = 26
    width = 8

    def __init__(self, pw):
        self.pw = pw
        self.palettes = [[0x050f42, 0x084c61, 0x0d94a3, 0xd34410, 0xff6e00],
                        [0x17313b, 0x414f47, 0x866d5c, 0xd5aaaa, 0xfff3e3],
                        list(reversed([0xc8bd00, 0xa6aaa5, 0x8faebe, 0x005b95, 0x010e1f])),
                        [0x100e15, 0x323e53, 0x408fb4, 0xbddfef, 0x64566e],
                        [0x0d0e12, 0x073245, 0x4886af, 0x83c1e8, 0xfcd5ce],
                        [0x010000, 0xa74c00, 0xffa100, 0xffd300, 0xf1f2f1],
                        [0x421930, 0x7c1e3b, 0xb44346, 0xd88e6c, 0xf6e7ce],
                        [0x002338, 0x009dd2, 0xffd898, 0xffca03, 0xa83a01],
                        [0x050831, 0x133072, 0xd5e6f7, 0xd5adfb, 0xf90052],
                        list(reversed([0x007f9f, 0x019c7c, 0x009f00, 0x006332, 0x001b00])),
                        [0x00070a, 0x294552, 0x597884, 0xacc4ce, 0x9eb9b3]]
        # default palette
        self.cur_palette = -1
        self.palette = self.palettes[self.cur_palette]
        self.sp_arrow = True
        self.hook = None
        return

    def on_mb_click(self, event, addr, size, mouse_offs):
        button = event.button()
        if button == Qt.MiddleButton:
            self.cur_palette = (self.cur_palette + 1) % len(self.palettes)
            self.palette = self.palettes[self.cur_palette]
        if button == Qt.RightButton:
            self.sp_arrow = not self.sp_arrow
            self.palette = self.palettes[self.cur_palette]


    def on_activate(self, idx):
        self.hook = DbgHook(self.pw)
        self.hook.hook()
        self.hook._request_update_viewer()
        return

    def on_deactivate(self):
        if self.hook is not None:
            self.hook.disable_timer()
            self.hook.unhook()
            self.hook = None
        return

    def on_get_annotations(self, address, size, mouse_offs):
        annotations = []
        sp = get_sp_val()
        ip = get_ip_val()
        fi = FrameInfo()

        if sp and ip:
            arrow = sp if self.sp_arrow else None
            frame_start_ea = fi.ea
            funcname = get_func_name(ip)

            annotations.append((None, None, "", None))
            annotations.append((arrow, self.palette[4], "[Stack Pointer]", self.palette[1]))
            annotations.append((None, None, " address: 0x%x" % (sp), self.palette[3]))
            sp_boundaries = fi.get_element_boundaries(sp)
            if sp_boundaries and len(fi.members):
                start, end = sp_boundaries
                name, offs, msize, foffs = fi.members[start]
                annotations.append((None,  None, " points to: %s" % (name), self.palette[3]))

            annotations.append((None, None, "", None))
            annotations.append((None, None, "[Function]", self.palette[1]))
            annotations.append((None, None, " name: %s" % (funcname), self.palette[3]))
            annotations.append((None, None, " frame addr: 0x%x" % (frame_start_ea), self.palette[3]))

            if mouse_offs and len(fi.members):
                mouse_boundaries = fi.get_element_boundaries(address+mouse_offs)
                if mouse_boundaries:
                    start, end = mouse_boundaries
                    name, offs, msize, foffs = fi.members[start]
                    # "dist" is the distance from current variable to
                    # end of stack frame this is where a return address
                    # may be stored depending on the CPU architecture
                    dist = foffs-offs
                    
                    # address of frame member in memory
                    var_addr = frame_start_ea+offs

                    # add annotations
                    annotations.append((None, None, "", None))
                    annotations.append((None, None, "[Frame Member]", self.palette[1]))
                    annotations.append((None, None, " name: %s" % (name), self.palette[3]))
                    annotations.append((None, None, " addr: 0x%x" % (var_addr), self.palette[3]))
                    annotations.append((None, None, " offs: Frame+0x%x" % (offs), self.palette[3]))
                    annotations.append((None, None, " size: 0x%x" % (msize), self.palette[3]))
                    annotations.append((None, None, " distance: %s0x%x" % ("-" if dist < 0 else "",
                        abs(dist)), self.palette[3]))
                    annotations.append((None, None, " cursor: %s+0x%x" % (name,
                        address + mouse_offs - (frame_start_ea+offs)),
                        self.palette[3]))



        else:
            annotations.append((None, None, "Debugger inactive", self.palette[4]))

        return annotations

    def on_process_buffer(self, buffers, addr, total, mouse_offs):
        colors = []
        goffs = 0
        mouse_boundaries = None

        sp = get_sp_val()
        ip = get_ip_val()
        fi = FrameInfo()

        if mouse_offs is not None:
            mouse_boundaries = fi.get_element_boundaries(addr+mouse_offs)

        for mapped, buf in buffers:
            if mapped:
                i = 0
                while i < len(buf):
                    # highlight stack var pointed to by mouse
                    if mouse_offs and mouse_boundaries:
                        start, end = mouse_boundaries

                        if addr + goffs + i in range(start, end):
                            size = min(end - start, total-i)
                            for j in range(size):
                                colors.append((True, self.palette[3]))
                            i += size
                            continue
                    # flash sp
                    if sp is not None and self.hook.highlighted and sp == addr + goffs + i:
                        size = get_item_size(sp)
                        boundaries = fi.get_element_boundaries(sp)
                        if boundaries:
                            start, end = boundaries
                            size = min(end - start, total-i)
                        for j in range(size):
                            colors.append((True, self.palette[4]))
                        i += size
                        continue
                    # locals
                    if goffs + addr + i in range(fi.ea, fi.ea + fi.framesize):
                        size = 1
                        boundaries = fi.get_element_boundaries(goffs + addr + i)
                        if boundaries: # if anything on the stackframe
                            start, end = boundaries
                            size = min(end - start, total-i)
                            for j in range(size):
                                colors.append((True, self.palette[2]))
                            i += size
                            continue
                        else: #gap between locals
                            colors.append((True, self.palette[1]))
                            i += 1
                            continue

                    # default bg color
                    colors.append((True, self.palette[0]))
                    i += 1

            # unmapped, transparency
            else:
                colors += [(False, None)]*len(buf)
            goffs += len(buf)
        
        return colors
   
def FILTER_INIT(pw):
    return StackyMcStackface(pw)

def FILTER_EXIT():
    return