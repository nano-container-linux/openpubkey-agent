package agent

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func findE2EScript() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		cand := filepath.Join(wd, "Tools", "e2e", "run_e2e.sh")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}
	return "", os.ErrNotExist
}

func TestCertificateFormatAcceptedBySshKeygen(t *testing.T) {
	script, err := findE2EScript()
	if err != nil {
		t.Skipf("e2e script not found: %v", err)
		return
	}
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("e2e script failed: %v\noutput: %s", err, string(out))
	}
}

func TestAgentRequestIdentitiesAndSign(t *testing.T) {
	tmp, err := os.MkdirTemp("", "agent_test_*")
	if err != nil {
		t.Fatalf("tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	socket := filepath.Join(tmp, "agent.sock")
	a := NewAgent(socket)
	if err := a.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}

	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := a.SetKeyAndCert(priv, nil); err != nil {
		t.Fatalf("set key: %v", err)
	}

	// connect
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// helper
	sshString := func(b []byte) []byte {
		out := make([]byte, 4+len(b))
		binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
		copy(out[4:], b)
		return out
	}
	writePacket := func(w io.Writer, payload []byte) error {
		var head [4]byte
		binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
		if _, err := w.Write(head[:]); err != nil {
			return err
		}
		_, err := w.Write(payload)
		return err
	}
	readFull := func(r io.Reader, n int) ([]byte, error) {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		return buf, err
	}

	// REQUEST_IDENTITIES (11)
	if err := writePacket(conn, []byte{11}); err != nil {
		t.Fatalf("write req ids: %v", err)
	}
	lenBuf, err := readFull(conn, 4)
	if err != nil {
		t.Fatalf("read len: %v", err)
	}
	respLen := int(binary.BigEndian.Uint32(lenBuf))
	resp, err := readFull(conn, respLen)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp[0] != 12 {
		t.Fatalf("expected identities answer (12), got %d", resp[0])
	}

	// SIGN_REQUEST (13)
	var keyInner []byte
	keyInner = append(keyInner, sshString([]byte("ssh-ed25519"))...)
	keyInner = append(keyInner, sshString(pub)...)
	keyBlob := sshString(keyInner)
	dataToSign := []byte("hello")
	var signReq []byte
	signReq = append(signReq, byte(13))
	signReq = append(signReq, keyBlob...)
	signReq = append(signReq, sshString(dataToSign)...)
	var flags [4]byte
	signReq = append(signReq, flags[:]...)
	if err := writePacket(conn, signReq); err != nil {
		t.Fatalf("write sign req: %v", err)
	}
	lenBuf, err = readFull(conn, 4)
	if err != nil {
		t.Fatalf("read sign len: %v", err)
	}
	sLen := int(binary.BigEndian.Uint32(lenBuf))
	sResp, err := readFull(conn, sLen)
	if err != nil {
		t.Fatalf("read sign resp: %v", err)
	}
	if sResp[0] != 14 {
		t.Fatalf("expected sign response (14), got %d", sResp[0])
	}
}

func TestAgentWorksWithSshAdd(t *testing.T) {
	tmp, err := os.MkdirTemp("", "agent_test_*")
	if err != nil {
		t.Fatalf("tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	socket := filepath.Join(tmp, "agent.sock")
	a := NewAgent(socket)
	if err := a.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}

	keyPath := filepath.Join(tmp, "user")
	cmd := exec.Command("/usr/bin/ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen failed: %v output:%s", err, string(out))
	}

	// ssh-add
	add := exec.Command("/usr/bin/ssh-add", keyPath)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	out, err = add.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-add failed: %v output:%s", err, string(out))
	}

	list := exec.Command("/usr/bin/ssh-add", "-L")
	list.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	out, err = list.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-add -L failed: %v output:%s", err, string(out))
	}
	outStr := string(out)

	pubData, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	parts := bytes.Fields(pubData)
	if len(parts) < 2 {
		t.Fatalf("unexpected pub format")
	}
	b64 := string(parts[1])
	if !bytes.Contains(out, []byte(b64)) && !bytes.Contains(out, []byte("ssh-ed25519")) {
		t.Fatalf("ssh-add -L output did not include our key: %s", outStr)
	}
}
