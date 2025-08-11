
# ----------
# File: addons/procmap.py (Windows-only best-effort PID mapping)
# ----------
import ctypes
import ctypes.wintypes as wt
import socket
import struct
import psutil

# Based on GetExtendedTcpTable for IPv4. Best effort.

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wt.DWORD),
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwRemoteAddr", wt.DWORD),
        ("dwRemotePort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wt.DWORD), ("table", MIB_TCPROW_OWNER_PID * 1)]

GetExtendedTcpTable = ctypes.windll.iphlpapi.GetExtendedTcpTable

class ProcMapper:
    def __init__(self):
        pass

    def _get_table(self):
        size = wt.ULONG(0)
        # First call to get required size
        GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        buf = ctypes.create_string_buffer(size.value)
        ret = GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        if ret != 0:
            return []
        # Read number of entries
        num = struct.unpack_from("I", buf, 0)[0]
        rows = []
        offset = 4
        for _ in range(num):
            row = struct.unpack_from("IIIII", buf, offset)
            pid = struct.unpack_from("I", buf, offset + 20)[0]
            rows.append((*row, pid))
            offset += 24
        return rows

    def lookup(self, local_ip: str, local_port: int):
        try:
            rows = self._get_table()
            lip = struct.unpack("!I", socket.inet_aton(local_ip))[0]
            lport_be = socket.htons(local_port)
            for state, laddr, lport, raddr, rport, pid in rows:
                if laddr == lip and lport == lport_be:
                    exe = None
                    try:
                        p = psutil.Process(pid)
                        exe = p.name()
                    except Exception:
                        pass
                    return int(pid), exe
        except Exception:
            pass
        return None, None
