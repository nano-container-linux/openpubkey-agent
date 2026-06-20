# OpenSSH Agent Protocol (PROTOCOL.agent)

## SSH2_AGENTC_REQUEST_IDENTITIES (0x0b)
Request a list of identities (public keys/certificates) held by the agent.

### Request:
- byte      SSH2_AGENTC_REQUEST_IDENTITIES (0x0b)

### Response (SSH2_AGENT_IDENTITIES_ANSWER, 0x0c):
- byte      SSH2_AGENT_IDENTITIES_ANSWER (0x0c)
- uint32    nkeys
- repeat nkeys times:
    - string   public key blob (binary SSH wire format, not text)
    - string   comment

## Notes
- The public key blob must be the SSH wire format for the key or certificate, as defined in RFC4253 and OpenSSH certificate spec.
- The agent must NOT send a base64-encoded or text public key line; it must send the raw binary blob.
- The comment is a UTF-8 string.
- The response is length-prefixed as per SSH protocol.

## References
- https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent
- https://datatracker.ietf.org/doc/html/rfc4253
- https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
