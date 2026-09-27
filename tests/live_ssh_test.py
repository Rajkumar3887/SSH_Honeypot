"""Live SSH smoke test — exercises every new feature."""
import paramiko, time, sys

TESTS = []
PASS  = []
FAIL  = []

def check(name, got, expected_substr):
    if expected_substr in got:
        PASS.append(name)
        print(f"  PASS  {name}  ->  {repr(got.strip()[:60])}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}  got={repr(got.strip()[:60])}  want={repr(expected_substr)}")

try:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=2223, username="admin", password="anything", timeout=8)
    chan = client.invoke_shell()
    time.sleep(1.2)
    chan.recv(4096)  # drain banner + prompt

    def send(cmd, wait=0.8):
        chan.send(cmd + "\n")
        time.sleep(wait)
        return chan.recv(4096).decode(errors="ignore")

    # 1. Basic command (case-insensitive — uppercase)
    out = send("WHOAMI")
    check("Case-insensitive command (WHOAMI)", out, "corpuser")

    # 2. Env-var expansion
    out = send("echo $USER")
    check("Env-var $USER", out, "corpuser")

    out = send("echo ${HOME}")
    check("Env-var ${HOME}", out, "/home/corpuser")

    # 3. Glob expansion
    out = send("ls /etc/p*")
    check("Glob /etc/p*", out, "passwd")

    # 4. Pipe: echo | wc -w
    out = send("echo hello world | wc -w")
    check("Pipe: echo | wc -w", out, "2")

    # 5. Pipe: grep on multi-line output
    out = send("cat /etc/passwd | grep root")
    check("Pipe: cat | grep root", out, "root")

    # 6. Pipe: head
    out = send("cat /etc/passwd | head -1")
    check("Pipe: cat | head -1", out, "root")

    # 7. Input validation — command too long
    long_cmd = "A" * 4097
    chan.send(long_cmd + "\n")
    time.sleep(1.5)
    out1 = chan.recv(4096).decode(errors="ignore")
    # The error may arrive in the same recv or the next one
    if "too long" not in out1:
        time.sleep(0.8)
        out1 += chan.recv(4096).decode(errors="ignore")
    check("Input validation (too-long cmd)", out1, "too long")

    # 8. Session still works after validation rejection
    out = send("whoami")
    check("Shell alive after validation error", out, "corpuser")

    # 9. Output truncation constant imported correctly
    out = send("echo $SHELL")
    check("Env-var $SHELL", out, "/bin/bash")

    # 10. cd + pwd updates correctly
    out = send("cd /tmp; pwd")
    check("cd + pwd", out, "/tmp")

    chan.send("exit\n")
    client.close()

except Exception as e:
    print(f"CONNECTION ERROR: {e}")
    sys.exit(1)

print()
print("=" * 50)
print(f"Live SSH Results: {len(PASS)} PASS  |  {len(FAIL)} FAIL")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
else:
    print("ALL LIVE TESTS PASSED [OK]")
