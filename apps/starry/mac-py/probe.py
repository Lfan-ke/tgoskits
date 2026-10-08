import os
import platform
import sys

print("MAC-PY", sys.version.split()[0], sys.platform, os.uname().sysname)
print("MAC-PY-PLATFORM", platform.platform())
