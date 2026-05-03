import os

# --- Platform Guard ---
# This prevents the script from crashing if tested on Windows
try:
    import fcntl
    import ctypes
    PLATFORM_SUPPORTED = True
except ImportError:
    PLATFORM_SUPPORTED = False

# Constants
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

def recv_notification(fd: int):
    # On Windows, we return a mock object so the supervisor loop can be tested
    if not PLATFORM_SUPPORTED: 
        return type('obj', (object,), {'id': 1234})()
    
    # Real Linux seccomp ioctl read would happen here
    return None

def send_allow(fd: int, notif_id: int):
    if not PLATFORM_SUPPORTED: 
        print("\033[90m[Bridge] Simulating SECCOMP_ALLOW to Kernel\033[0m")
    
def send_deny(fd: int, notif_id: int, errno: int = -1):
    if not PLATFORM_SUPPORTED: 
        print("\033[90m[Bridge] Simulating SECCOMP_DENY (EPERM) to Kernel\033[0m")
