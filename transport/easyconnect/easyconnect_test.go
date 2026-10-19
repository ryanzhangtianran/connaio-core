package easyconnect

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestTOTPMatchesTheRFC6238Vectors(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	for unix, want := range map[int64]string{59: "287082", 1_111_111_109: "081804", 1_234_567_890: "005924"} {
		if got, err := totp(secret, unix); err != nil || got != want {
			t.Errorf("totp(%d) = %q, %v; want %q", unix, got, err, want)
		}
	}
}

func TestHTTPBodiesAreReadToTheirLengthThroughChunksOrToTheEnd(t *testing.T) {
	read := func(raw string) (*response, error) { return readResponse(strings.NewReader(raw)) }
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<Aut\r\n2\r\nh>\r\n0\r\n\r\n"
	if r, err := read(chunked); err != nil || r.body != "<Auth>" {
		t.Errorf("chunked: %+v %v", r, err)
	}
	if _, err := read(chunked[:len(chunked)-7]); err == nil {
		t.Error("an incomplete chunked body was accepted")
	}
	if r, err := read("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno"); err != nil || r.status != 404 || r.body != "no" {
		t.Errorf("sized: %+v %v", r, err)
	}
	if r, err := read("HTTP/1.0 200 OK\r\n\r\nrest"); err != nil || r.body != "rest" {
		t.Errorf("open: %+v %v", r, err)
	}
	if _, err := read("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nx\r\n0\r\n\r\n"); err == nil {
		t.Error("an overflowing chunk size was accepted")
	}
	if _, err := read("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nno"); err == nil {
		t.Error("a negative Content-Length was accepted")
	}
}

func TestTheResourceListBecomesRangesDomainsAndResolvers(t *testing.T) {
	routing := parseRouting(`
		<Resource><Rcs>
		<Rc id="1" type="1" proto="0" host="10.0.0.0~10.255.255.255;https://git.example.edu.cn/x;10.1.2.3:2222" port="1~65535;0~0;0~0" />
		<Rc id="2" type="0" proto="0" host="192.168.0.1" port="80~80" />
		</Rcs><Dns dnsserver="10.10.0.21;10.10.0.22;" data="" /></Resource>`)
	addr := netip.MustParseAddr
	want := []Range{{addr("10.0.0.0"), addr("10.255.255.255"), 1, 65535, "tcp"}, {addr("10.1.2.3"), addr("10.1.2.3"), 2222, 2222, "tcp"}}
	if !reflect.DeepEqual(routing.IP, want) {
		t.Errorf("ip = %+v", routing.IP)
	}
	if !reflect.DeepEqual(routing.Domains, []string{"git.example.edu.cn"}) || !reflect.DeepEqual(routing.DNS, []string{"10.10.0.21", "10.10.0.22"}) {
		t.Errorf("domains %v dns %v", routing.Domains, routing.DNS)
	}
	for host, want := range map[string]bool{"git.example.edu.cn": true, "a.git.example.edu.cn": true, "xgit.example.edu.cn": false, "example.com": false} {
		if routing.MatchHost(host) != want {
			t.Errorf("MatchHost(%s) != %v", host, want)
		}
	}
	if !routing.MatchIP(addr("10.1.2.3"), 2222, "tcp") || routing.MatchIP(addr("10.1.2.3"), 2222, "udp") || routing.MatchIP(addr("11.0.0.1"), 80, "tcp") {
		t.Error("MatchIP")
	}
}

func TestASealedRecordOpensAgain(t *testing.T) {
	key, mac := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{9}, 20)
	for _, useRC4 := range []bool{true, false} {
		out, back := newCipherState(key, mac, useRC4), newCipherState(key, mac, useRC4)
		for _, message := range [][]byte{[]byte("packet"), make([]byte, 100)} {
			sealed := out.seal(23, versionTLS11, message, nil)
			opened, err := back.open(23, versionTLS11, sealed)
			if err != nil || !bytes.Equal(opened, message) {
				t.Errorf("rc4=%v: %v %q", useRC4, err, opened)
			}
		}
	}
}

// The record must be plain, then HMAC-SHA1 over sequence, type, version,
// length and plain, under RC4.
func TestAnRC4RecordIsWhatTLSSays(t *testing.T) {
	key, macKey := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{9}, 20)
	plain := []byte("packet")
	sealed := newCipherState(key, macKey, true).seal(23, versionTLS11, plain, nil)
	m := hmac.New(sha1.New, macKey)
	m.Write(append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 23, 3, 2, 0, byte(len(plain))}, plain...))
	expected := append(append([]byte{}, plain...), m.Sum(nil)...)
	c, _ := rc4.NewCipher(key)
	c.XORKeyStream(expected, expected)
	if !bytes.Equal(sealed, expected) {
		t.Errorf("sealed %x, want %x", sealed, expected)
	}
}

// Records read back to back must not share bytes with what an earlier Read returned once copied,
// and the seal/open pair must survive the buffer reuse.
func TestConsecutiveReadsReuseTheBufferButNotTheData(t *testing.T) {
	key, mac := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{9}, 20)
	writer, reader := newCipherState(key, mac, true), newCipherState(key, mac, true)
	var wire []byte
	for _, m := range []string{"first", "second"} {
		wire = (&tlsConn{version: versionTLS11, writer: writer}).appendRecord(recordApplicationData, []byte(m), wire)
	}
	c := &tlsConn{version: versionTLS11, reader: reader, r: bufio.NewReader(bytes.NewReader(wire))}
	first, err := c.Read()
	if err != nil || string(first) != "first" {
		t.Fatalf("%v %q", err, first)
	}
	kept := append([]byte(nil), first...)
	second, err := c.Read()
	if err != nil || string(second) != "second" || string(kept) != "first" {
		t.Fatalf("%v %q kept %q", err, second, kept)
	}
}

// Against a local server, run by hand. For the tunnel hello (system LibreSSL;
// Homebrew's OpenSSL has no RC4):
//
//	openssl s_server -accept 4433 -cert c.pem -key k.pem -www -tls1_1 -cipher RC4-SHA
//	EC_TLS_SERVER=127.0.0.1:4433 EC_TLS_TUNNEL=1 go test ./transport/easyconnect -run Live -v
//
// For the portal hello, drop -tls1_1 and use -cipher 'AES128-SHA' and no EC_TLS_TUNNEL.
func TestLiveTLS(t *testing.T) {
	server := os.Getenv("EC_TLS_SERVER")
	if server == "" {
		t.Skip("EC_TLS_SERVER not set")
	}
	raw, err := net.Dial("tcp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c, err := handshake(raw, hello{tunnel: os.Getenv("EC_TLS_TUNNEL") != "", serverName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := c.Read()
	if err != nil || !bytes.HasPrefix(reply, []byte("HTTP/1.0 200")) {
		t.Fatalf("%v %q", err, reply)
	}
	if len(c.sessionID) == 0 {
		t.Error("no session ID")
	}
	t.Logf("version %04x, session ID %x", c.version, c.sessionID)
}

func TestFieldsLoseTheirCDATAAndOnlyCredentialErrorsAreRefused(t *testing.T) {
	if got := field("Message", "<Auth><Message><![CDATA[incorrect svpn_req_randcode]]></Message></Auth>"); got != "incorrect svpn_req_randcode" {
		t.Errorf("field = %q", got)
	}
	var refusedErr *RefusedError
	if !errors.As(loginError("用户名或密码错误"), &refusedErr) || errors.As(loginError("incorrect svpn_req_randcode"), &refusedErr) {
		t.Error("loginError classification")
	}
}

func TestRoutingWithout(t *testing.T) {
	a := netip.MustParseAddr
	r := Routing{
		IP:      []Range{{From: a("10.0.0.1"), To: a("10.255.255.254")}, {From: a("10.90.63.2"), To: a("10.90.63.2")}, {From: a("1.0.0.1"), To: a("9.255.255.254")}},
		Domains: []string{"hkust-gz.edu.cn", "example.edu.cn"},
	}
	got := r.Without([]string{"1.0.0.1-9.255.255.254", "10.90.63.2", "example.edu.cn"})
	if len(got.IP) != 1 || got.IP[0].Key() != "10.0.0.1-10.255.255.254" || !reflect.DeepEqual(got.Domains, []string{"hkust-gz.edu.cn"}) {
		t.Fatalf("Without = %+v", got)
	}
	if len(r.IP) != 3 || len(r.Domains) != 2 {
		t.Fatalf("Without changed the original: %+v", r)
	}
}
