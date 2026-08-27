import sys; sys.path.insert(0, '/pipeline')
from duo_automation import _winrm_connect
sess = _winrm_connect()
r = sess.run_cmd('powershell', ['-Command',
    r'Get-Content "C:\ProgramData\Duo Security Authentication Proxy\log\authproxy.log" -Tail 40'])
out = r.std_out.decode('utf-8', 'replace')
print(out[-3000:] if out else '(empty)')
print("RC:", r.status_code, "ERR:", r.std_err.decode()[:100])
