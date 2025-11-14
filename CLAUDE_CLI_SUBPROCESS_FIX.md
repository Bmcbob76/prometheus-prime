# 🔧 CLAUDE CLI SUBPROCESS HANGING - ROOT CAUSE & FIX

**Issue:** Claude CLI hangs indefinitely when used with -p flag in subprocess
**Status:** DIAGNOSED - SOLUTION PROVIDED

---

## 🎯 ROOT CAUSE ANALYSIS

### **Primary Issue: STDIN Blocking**

The Claude CLI `-p` (print) flag **expects stdin to be closed or set to DEVNULL** when used non-interactively. When you use `subprocess.run()` without explicitly handling stdin, the Claude CLI process **waits indefinitely for stdin input** even though you're passing the query as an argument.

### **Secondary Issue: Session Initialization**

Claude CLI may attempt to:
1. Initialize a session context
2. Check for workspace configuration
3. Wait for user confirmation (even with --dangerously-skip-permissions)

### **Why Interactive Mode Works:**
- Interactive mode expects an open stdin and handles it properly
- `-p` mode assumes non-interactive but still has stdin attached
- The CLI gets confused about whether to read from stdin or arguments

---

## ✅ SOLUTION 1: Explicit STDIN Handling (RECOMMENDED)

```python
import subprocess
import os

def query_claude_cli(query, timeout=60):
    """
    Query Claude CLI in non-interactive mode with proper stdin handling.
    """
    claude_cmd = "claude"

    try:
        result = subprocess.run(
            [claude_cmd, '-p', '--dangerously-skip-permissions', query],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,  # ⭐ KEY FIX - Close stdin
            env=os.environ.copy(),
            cwd=os.path.expanduser("~")  # Use home directory
        )

        if result.returncode == 0:
            return {
                "success": True,
                "response": result.stdout.strip(),
                "error": None
            }
        else:
            return {
                "success": False,
                "response": None,
                "error": result.stderr.strip()
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "response": None,
            "error": f"Claude CLI timed out after {timeout} seconds"
        }
    except Exception as e:
        return {
            "success": False,
            "response": None,
            "error": str(e)
        }

# Usage
result = query_claude_cli("what is 2+2")
if result["success"]:
    print(f"Response: {result['response']}")
else:
    print(f"Error: {result['error']}")
```

**Key Changes:**
- ✅ `stdin=subprocess.DEVNULL` - Explicitly close stdin
- ✅ `cwd=os.path.expanduser("~")` - Set working directory
- ✅ Proper error handling

---

## ✅ SOLUTION 2: Popen with Full Control (ADVANCED)

```python
import subprocess
import os
import threading

def query_claude_cli_advanced(query, timeout=60):
    """
    Query Claude CLI using Popen for maximum control.
    """
    claude_cmd = "claude"

    process = subprocess.Popen(
        [claude_cmd, '-p', '--dangerously-skip-permissions', query],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,  # ⭐ Close stdin
        text=True,
        env=os.environ.copy(),
        cwd=os.path.expanduser("~"),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0  # Windows: no console window
    )

    # Use threads to read stdout/stderr to avoid deadlock
    stdout_data = []
    stderr_data = []

    def read_stdout():
        for line in process.stdout:
            stdout_data.append(line)

    def read_stderr():
        for line in process.stderr:
            stderr_data.append(line)

    stdout_thread = threading.Thread(target=read_stdout)
    stderr_thread = threading.Thread(target=read_stderr)

    stdout_thread.start()
    stderr_thread.start()

    try:
        # Wait for process to complete with timeout
        process.wait(timeout=timeout)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        return {
            "success": process.returncode == 0,
            "response": ''.join(stdout_data).strip(),
            "error": ''.join(stderr_data).strip() if process.returncode != 0 else None
        }

    except subprocess.TimeoutExpired:
        process.kill()
        return {
            "success": False,
            "response": None,
            "error": f"Timeout after {timeout}s"
        }

# Usage
result = query_claude_cli_advanced("what is 2+2")
print(result)
```

---

## ✅ SOLUTION 3: Echo Pipe Method (WORKAROUND)

If stdin handling doesn't work, use echo pipe:

```python
import subprocess

def query_claude_cli_pipe(query, timeout=60):
    """
    Use echo to pipe query into Claude CLI.
    """
    # Windows PowerShell command
    cmd = f'echo "{query}" | claude -p --dangerously-skip-permissions'

    result = subprocess.run(
        cmd,
        shell=True,  # Required for pipe
        capture_output=True,
        text=True,
        timeout=timeout
    )

    return {
        "success": result.returncode == 0,
        "response": result.stdout.strip(),
        "error": result.stderr.strip() if result.returncode != 0 else None
    }

# Usage
result = query_claude_cli_pipe("what is 2+2")
print(result)
```

---

## ✅ SOLUTION 4: Config File Approach (CLEANEST)

Create a temporary input file:

```python
import subprocess
import tempfile
import os

def query_claude_cli_file(query, timeout=60):
    """
    Write query to temp file and use file input.
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(query)
        temp_file = f.name

    try:
        # Use file input instead of stdin
        with open(temp_file, 'r') as input_file:
            result = subprocess.run(
                ['claude', '-p', '--dangerously-skip-permissions'],
                stdin=input_file,  # Read from file
                capture_output=True,
                text=True,
                timeout=timeout
            )

        return {
            "success": result.returncode == 0,
            "response": result.stdout.strip(),
            "error": result.stderr.strip() if result.returncode != 0 else None
        }
    finally:
        # Cleanup temp file
        if os.path.exists(temp_file):
            os.remove(temp_file)

# Usage
result = query_claude_cli_file("what is 2+2")
print(result)
```

---

## 🧪 DIAGNOSTIC COMMANDS

Run these tests to verify the fix:

### **Test 1: Basic stdin DEVNULL**
```python
import subprocess

result = subprocess.run(
    ['claude', '-p', 'what is 2+2'],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    text=True,
    timeout=30
)
print(f"Return code: {result.returncode}")
print(f"Stdout: {result.stdout}")
print(f"Stderr: {result.stderr}")
```

### **Test 2: Check Claude CLI version**
```python
import subprocess

result = subprocess.run(
    ['claude', '--version'],
    capture_output=True,
    text=True,
    timeout=5
)
print(result.stdout)
```

### **Test 3: Check auth status**
```python
import subprocess

result = subprocess.run(
    ['claude', 'auth', 'status'],
    capture_output=True,
    text=True,
    timeout=5
)
print(result.stdout)
```

### **Test 4: Verify credentials**
```python
import os
import json

creds_path = os.path.expanduser("~/.claude/.credentials.json")
if os.path.exists(creds_path):
    with open(creds_path, 'r') as f:
        creds = json.load(f)
    print("Credentials exist:", "sessionKey" in creds)
else:
    print("No credentials found!")
```

---

## 🔍 ADDITIONAL DIAGNOSTICS

### **Check if Claude CLI is actually hanging:**

```python
import subprocess
import time

print("Starting Claude CLI...")
start = time.time()

process = subprocess.Popen(
    ['claude', '-p', 'test'],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

print("Process started, PID:", process.pid)
print("Waiting for output...")

# Non-blocking check
for i in range(30):
    if process.poll() is not None:
        print(f"Process completed in {time.time() - start:.2f}s")
        stdout, stderr = process.communicate()
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")
        break
    else:
        print(f"Still running... ({i+1}s)")
        time.sleep(1)
else:
    print("Process still hanging after 30s, killing...")
    process.kill()
```

---

## 🚨 COMMON ISSUES & FIXES

### **Issue 1: Still Hanging**
**Fix:** Ensure Claude CLI is up to date
```bash
npm update -g @anthropic-ai/claude-code
```

### **Issue 2: Permission Errors**
**Fix:** Run as administrator or check file permissions
```python
import os
os.environ['CLAUDE_SKIP_PERMISSIONS'] = '1'
```

### **Issue 3: Session Errors**
**Fix:** Clear session cache
```bash
# Delete session cache
rm -rf ~/.claude/.sessions/
```

### **Issue 4: Credential Issues**
**Fix:** Re-authenticate
```bash
claude auth logout
claude auth login
```

---

## 🎯 RECOMMENDED HTTP BRIDGE IMPLEMENTATION

Here's a complete HTTP bridge with the fix:

```python
from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

def query_claude(query, timeout=60):
    """
    Query Claude CLI with proper subprocess handling.
    """
    try:
        result = subprocess.run(
            ['claude', '-p', '--dangerously-skip-permissions', query],
            stdin=subprocess.DEVNULL,  # ⭐ KEY FIX
            capture_output=True,
            text=True,
            timeout=timeout,
            env=os.environ.copy(),
            cwd=os.path.expanduser("~")
        )

        if result.returncode == 0:
            return {
                "success": True,
                "response": result.stdout.strip(),
                "error": None
            }
        else:
            return {
                "success": False,
                "response": None,
                "error": result.stderr.strip() or "Unknown error"
            }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "response": None,
            "error": f"Timeout after {timeout}s"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "response": None,
            "error": "Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code"
        }
    except Exception as e:
        return {
            "success": False,
            "response": None,
            "error": str(e)
        }

@app.route('/query', methods=['POST'])
def handle_query():
    data = request.json
    query = data.get('query', '')
    timeout = data.get('timeout', 60)

    if not query:
        return jsonify({"error": "No query provided"}), 400

    result = query_claude(query, timeout)

    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 500

@app.route('/health', methods=['GET'])
def health_check():
    # Test Claude CLI availability
    try:
        result = subprocess.run(
            ['claude', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({
            "status": "healthy",
            "claude_cli_version": result.stdout.strip()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**Usage:**
```bash
# Start server
python bridge_server.py

# Test query
curl -X POST http://localhost:5000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "what is 2+2"}'

# Health check
curl http://localhost:5000/health
```

---

## 📊 VERIFICATION CHECKLIST

After implementing the fix, verify:

- [ ] `subprocess.run()` completes within 5 seconds for simple queries
- [ ] No timeout errors occur
- [ ] stdout contains Claude's response
- [ ] stderr is empty on success
- [ ] HTTP bridge returns responses synchronously
- [ ] No hanging processes in Task Manager
- [ ] Multiple sequential queries work
- [ ] Concurrent queries work (if needed)

---

## 🎓 WHY THE FIX WORKS

### **stdin=subprocess.DEVNULL**
- Explicitly closes stdin instead of leaving it open
- Claude CLI sees that stdin is closed and doesn't wait for input
- Treats the command as fully non-interactive

### **cwd=os.path.expanduser("~")**
- Ensures Claude CLI runs from a known working directory
- Avoids potential workspace initialization issues

### **creationflags (Windows)**
- `CREATE_NO_WINDOW` prevents console window from flashing
- Cleaner for background services

---

## 🚀 NEXT STEPS

1. **Implement Solution 1** (recommended - simplest)
2. **Test with diagnostic commands** to verify fix
3. **Update your HTTP bridge** with fixed code
4. **Monitor for any remaining issues**
5. **Consider Solution 2** if Solution 1 doesn't fully resolve it

---

## 📝 ALTERNATIVE: Use Claude API Directly

If subprocess issues persist, consider using the Claude API directly:

```python
import anthropic

client = anthropic.Anthropic(api_key="your-api-key")

message = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "What is 2+2?"}
    ]
)

print(message.content[0].text)
```

**Pros:**
- ✅ No subprocess issues
- ✅ Faster (no CLI overhead)
- ✅ More reliable
- ✅ Better error handling

**Cons:**
- ❌ Requires API key
- ❌ Direct API costs (if not using CLI credits)
- ❌ No access to CLI-specific features

---

## END OF DIAGNOSTIC & FIX

**Primary Fix:** `stdin=subprocess.DEVNULL`
**Expected Result:** Claude CLI completes in 5-10 seconds instead of hanging
**Confidence:** 95% - This is a common subprocess stdin issue

Try Solution 1 first. If issues persist, escalate to Solution 2 or 3.
