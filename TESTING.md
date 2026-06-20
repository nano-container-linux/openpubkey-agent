# opkssh/OpenPubkeyAgent Integration Test (macOS)

## Prerequisites
- Build and run your OpenPubkeyAgent app (it must be running and the agent loaded)
- Install opkssh (e.g. via Homebrew: `brew install opkssh`)
- Ensure the environment variable `SSH_AUTH_SOCK` is set to `/tmp/openpubkey-agent.sock`

## Manual Test Steps
1. In the OpenPubkeyAgent menu, click "Login & Load SSH Key" to load a key/cert in memory.
2. In a terminal, run:

    ssh-add -l -E sha256

   You should see a single OpenPubkey SSH certificate listed (with a comment like "OpenPubkey SSH Cert").

3. Test with opkssh:

    opkssh login --agent

   This should use the agent and not require a key on disk.

4. (Optional) Try SSH to a server configured for OpenPubkey/opkssh.

---

## Automated Test (Swift)

This script connects to the agent socket, sends a SSH2_AGENTC_REQUEST_IDENTITIES message, and checks the response.

```
import Foundation

let sockPath = "/tmp/openpubkey-agent.sock"
let fd = socket(AF_UNIX, SOCK_STREAM, 0)
var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
strcpy(&addr.sun_path.0, sockPath)
let len = UInt8(MemoryLayout.size(ofValue: addr))
let result = withUnsafePointer(to: &addr) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(fd, $0, socklen_t(len))
    }
}
guard result == 0 else { fatalError("Failed to connect to agent") }
// Send SSH2_AGENTC_REQUEST_IDENTITIES
var msg = Data()
msg.append(UInt32(1 + 0).bigEndianData) // length
msg.append(11) // SSH2_AGENTC_REQUEST_IDENTITIES
msg.withUnsafeBytes { ptr in
    write(fd, ptr.baseAddress, msg.count)
}
// Read response
var lenBuf = [UInt8](repeating: 0, count: 4)
read(fd, &lenBuf, 4)
let respLen = UInt32(bigEndian: Data(lenBuf).withUnsafeBytes { $0.load(as: UInt32.self) })
var respBuf = [UInt8](repeating: 0, count: Int(respLen))
read(fd, &respBuf, Int(respLen))
print("Agent response:", Data(respBuf))
close(fd)
```

- Compile and run with:

    swiftc -o agent-test agent-test.swift && ./agent-test

- The output should show a response with type 12 (SSH2_AGENT_IDENTITIES_ANSWER) and one identity.

---

## Troubleshooting
- If `ssh-add -l` or the test script fails, ensure the agent is running and the menu action was used to load a key.
- Check that `SSH_AUTH_SOCK` is set and points to `/tmp/openpubkey-agent.sock`.
- Use `lsof | grep openpubkey-agent.sock` to verify the socket is open.
