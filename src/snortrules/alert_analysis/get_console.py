import subprocess
import sys
import tempfile

with tempfile.TemporaryFile() as tempf:
    proc = subprocess.Popen(['snort', '-c', '/usr/local/etc/snort/snort.lua', '-i', 'eth0', '-R',
                             '~/zhechang/oneRule.rules', '-A', 'alert_fast', '-k', 'none'], stdout=tempf)
    proc.wait()
    tempf.seek(0)
    print(tempf.read())