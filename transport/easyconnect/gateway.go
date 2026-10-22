package easyconnect

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
)

// Everything that talks to the gateway itself, as opposed to through it.
//
// The flow runs in this order. /por/login_auth.csp returns a session ID
// (TWFID) and an RSA key. /por/login_psw.csp, plus /por/login_token.csp for a
// TOTP second factor, authorises that session. The next handshake binds the
// TWFID to a TLS session ID, and the two together form the token. The token
// is exchanged for a tunnel address. From then on, two TLS streams carry raw
// IP packets, one in each direction.

// Dialer opens a TCP connection to the gateway on the physical network. The
// kernel's dialer does the interface binding and name resolution.
type Dialer func(ctx context.Context) (net.Conn, error)

// requestTimeout bounds one exchange with the gateway, handshake included.
const requestTimeout = 30 * time.Second

type Gateway struct {
	Host string
	Port int
	dial Dialer

	twfid   string
	token   []byte
	address [4]byte
}

type response struct {
	status int
	body   string
}

func NewGateway(host string, port int, dial Dialer) *Gateway {
	return &Gateway{Host: host, Port: port, dial: dial}
}

func (g *Gateway) authority() string {
	if g.Port == 443 {
		return g.Host
	}
	return net.JoinHostPort(g.Host, strconv.Itoa(g.Port))
}

// Login authorises a fresh TWFID with a username, password and optional TOTP secret.
func (g *Gateway) Login(ctx context.Context, username, password, totpSecret string) error {
	auth, err := g.request(ctx, "GET", "/por/login_auth.csp?apiversion=1", nil)
	if err != nil {
		return err
	}
	twfid, modulus := field("TwfID", auth.body), field("RSA_ENCRYPT_KEY", auth.body)
	if twfid == "" || modulus == "" {
		return fmt.Errorf("unexpected login_auth reply: %s", prefix(auth.body))
	}
	g.twfid = twfid
	if field("RndImg", auth.body) == "1" {
		return unsupported("a picture captcha")
	}

	csrf := field("CSRF_RAND_CODE", auth.body)
	secret := password
	if csrf != "" {
		secret = password + "_" + csrf
	}
	exponent := 65537
	if e, err := strconv.Atoi(field("RSA_ENCRYPT_EXP", auth.body)); err == nil {
		exponent = e
	}
	n, ok := new(big.Int).SetString(modulus, 16)
	if !ok {
		return errors.New("RSA: the gateway sent an unusable key")
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{N: n, E: exponent}, []byte(secret))
	if err != nil {
		return fmt.Errorf("RSA: %w", err)
	}

	reply, err := g.request(ctx, "POST", "/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs", [][2]string{
		{"svpn_rand_code", ""}, {"mitm", ""}, {"svpn_req_randcode", csrf},
		{"svpn_name", username}, {"svpn_password", hex.EncodeToString(encrypted)},
	})
	if err != nil {
		return err
	}
	next := field("NextAuth", reply.body)
	if strings.Contains(reply.body, "<NextService>auth/token</NextService>") || next == "7" {
		if totpSecret == "" {
			return refused("the account needs a TOTP code, and no TOTP secret was given")
		}
		code, err := totp(totpSecret, time.Now().Unix())
		if err != nil {
			return err
		}
		return g.loginTOTP(ctx, code)
	}
	if strings.Contains(reply.body, "<NextService>auth/sms</NextService>") || next == "2" {
		return unsupported("an SMS code")
	}
	switch next {
	case "0":
		return unsupported("a client certificate")
	case "", "-1":
	default:
		return unsupported("second factor " + next)
	}
	if field("Result", reply.body) != "1" {
		if m := field("Message", reply.body); m != "" {
			return loginError(m)
		}
		return errors.New(prefix(reply.body))
	}
	if updated := field("TwfID", reply.body); updated != "" {
		g.twfid = updated
	}
	return nil
}

func (g *Gateway) loginTOTP(ctx context.Context, code string) error {
	reply, err := g.request(ctx, "POST", "/por/login_token.csp", [][2]string{{"svpn_inputtoken", code}})
	if err != nil {
		return err
	}
	if updated := field("TwfID", reply.body); updated != "" && strings.Contains(reply.body, "Totp auth succ") {
		g.twfid = updated
		return nil
	}
	if m := field("Message", reply.body); m != "" {
		return refused("TOTP rejected: " + m)
	}
	return refused("TOTP rejected: " + prefix(reply.body))
}

// RequestToken binds the TWFID to a TLS session. The token is the first 31
// hex digits of that session's ID, a NUL, then the TWFID.
func (g *Gateway) RequestToken(ctx context.Context) error {
	tls, err := g.connect(ctx, hello{serverName: g.Host})
	if err != nil {
		return err
	}
	defer tls.Close()
	authority, cookie := g.authority(), "Cookie: TWFID="+g.twfid+"\r\n\r\n"
	err = tls.Write([]byte("GET /por/conf.csp HTTP/1.1\r\nHost: " + authority + "\r\n" + cookie +
		"GET /por/rclist.csp HTTP/1.1\r\nHost: " + authority + "\r\n" + cookie))
	if err != nil {
		return err
	}
	if _, err := tls.Read(); err != nil {
		return err
	}

	session := hex.EncodeToString(tls.sessionID)
	token := []byte(session[:min(len(session), 31)])
	token = append(token, 0)
	token = append(token, g.twfid...)
	if len(session) < 31 || len(token) != 48 {
		return fmt.Errorf("cannot form a tunnel token (session ID %d bytes, TWFID %d characters)", len(tls.sessionID), len(g.twfid))
	}
	g.token = token
	return nil
}

// RequestAddress exchanges the token for a tunnel address. The connection
// that asked must stay open for the tunnel's lifetime, so it is returned.
func (g *Gateway) RequestAddress(ctx context.Context) (*tlsConn, error) {
	tls, err := g.connect(ctx, hello{tunnel: true})
	if err != nil {
		return nil, err
	}
	msg := append([]byte{0, 0, 0, 0}, g.token...)
	msg = append(msg, make([]byte, 8)...)
	msg = append(msg, 0xFF, 0xFF, 0xFF, 0xFF)
	if err := tls.Write(msg); err != nil {
		tls.Close()
		return nil, err
	}
	reply, err := tls.Read()
	if err != nil {
		tls.Close()
		return nil, err
	}
	if len(reply) < 8 || reply[0] != 0 {
		tls.Close()
		return nil, errors.New("the gateway refused a tunnel address")
	}
	copy(g.address[:], reply[4:8])
	_ = tls.SetDeadline(time.Time{})
	return tls, nil
}

// OpenTunnel opens one direction of the packet tunnel. The command byte is 5
// to send and 6 to receive.
//
// Keepalive probes after thirty idle seconds make a dead path, such as a NAT
// mapping that expired, fail within a minute instead of blocking a read
// forever, so the stream is reopened.
func (g *Gateway) OpenTunnel(ctx context.Context, sending bool) (*tlsConn, error) {
	tls, err := g.connect(ctx, hello{tunnel: true})
	if err != nil {
		return nil, err
	}
	if tcp, ok := N.FindUpstream[*net.TCPConn](tls.raw, nil); ok { // through any wrapper the dialer added
		_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3})
	}
	command := byte(6)
	if sending {
		command = 5
	}
	msg := append([]byte{command, 0, 0, 0}, g.token...)
	msg = append(msg, make([]byte, 8)...)
	msg = append(msg, g.address[3], g.address[2], g.address[1], g.address[0])
	if err := tls.Write(msg); err != nil {
		tls.Close()
		return nil, err
	}
	reply, err := tls.Read()
	if err != nil {
		tls.Close()
		return nil, err
	}
	var first byte = 0xFF
	if len(reply) > 0 {
		first = reply[0]
	}
	switch {
	case sending && first == 0x02, !sending && first == 0x01:
		_ = tls.SetDeadline(time.Time{})
		return tls, nil
	case first == 0x08:
		err = ErrSessionEnded
	case first >= 0x05 && first <= 0x07, first == 0x09:
		err = errors.New("the gateway is busy; try again")
	default:
		err = fmt.Errorf("unexpected tunnel reply %v", reply)
	}
	tls.Close()
	return nil, err
}

// UpdateSession keeps the session from being closed as idle, as the official
// client does. Returns false if the gateway doesn't support it.
func (g *Gateway) UpdateSession(ctx context.Context) bool {
	r, err := g.request(ctx, "GET", "/por/update_session.csp?apiversion=1&twfid="+g.twfid, nil)
	return err != nil || r.status != 404
}

// Logout ends the gateway's web session, as the official client does on exit. Without it the
// session lingers until the gateway's idle timeout, and the next login for the account is
// refused a tunnel address. Best effort, bounded.
func (g *Gateway) Logout() {
	if g.twfid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = g.request(ctx, "GET", "/por/logout.csp?apiversion=1", nil)
}

// Resources is what the gateway will route for this session.
func (g *Gateway) Resources(ctx context.Context) (Routing, error) {
	r, err := g.request(ctx, "GET", "/por/rclist.csp", nil)
	if err != nil {
		return Routing{}, err
	}
	return parseRouting(r.body), nil
}

// connect is a TLS connection to the gateway on the physical network, with a
// deadline on the handshake; tunnel streams clear it once they are open.
func (g *Gateway) connect(ctx context.Context, h hello) (*tlsConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := g.dial(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", g.authority(), err)
	}
	deadline := time.Now().Add(requestTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) { // a bounded caller (Logout) stays bounded
		deadline = d
	}
	_ = raw.SetDeadline(deadline)
	tls, err := handshake(raw, h)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return tls, nil
}

func (g *Gateway) request(ctx context.Context, method, path string, form [][2]string) (*response, error) {
	tls, err := g.connect(ctx, hello{serverName: g.Host})
	if err != nil {
		return nil, err
	}
	defer tls.Close()
	head := method + " " + path + " HTTP/1.1\r\nHost: " + g.authority() + "\r\nUser-Agent: EasyConnect_windows\r\nConnection: close\r\n"
	if g.twfid != "" {
		head += "Cookie: TWFID=" + g.twfid + "\r\n"
	}
	var body string
	if form != nil {
		parts := make([]string, len(form))
		for i, kv := range form {
			parts[i] = kv[0] + "=" + url.QueryEscape(kv[1])
		}
		body = strings.Join(parts, "&")
		head += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	if err := tls.Write([]byte(head + "\r\n" + body)); err != nil {
		return nil, err
	}

	r, err := readResponse(&recordReader{c: tls})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// readResponse reads one HTTP/1.x response whole: to its Content-Length, through its chunks, or
// to the end of the connection.
func readResponse(r io.Reader) (*response, error) {
	resp, err := http.ReadResponse(bufio.NewReader(r), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // a resource list is kilobytes; a root daemon's heap isn't the place for a runaway body
	if err != nil {
		return nil, err
	}
	return &response{status: resp.StatusCode, body: string(body)}, nil
}

// recordReader reads a tlsConn as a byte stream, one record at a time; a closed connection is EOF.
type recordReader struct {
	c    *tlsConn
	rest []byte
}

func (r *recordReader) Read(p []byte) (int, error) {
	for len(r.rest) == 0 {
		rec, err := r.c.Read()
		if errors.Is(err, ErrClosed) {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		r.rest = rec
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

// ErrSessionEnded is the gateway closing the tunnel on its side: the session expired, or the
// account signed in somewhere else (a gateway allows one session per account).
var ErrSessionEnded = errors.New("the gateway ended the session")

// RefusedError is a login the gateway turned down for a reason that won't change until the
// settings do: wrong credentials, a second factor this client can't provide. Not worth retrying.
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return e.Msg }

func refused(msg string) error { return &RefusedError{Msg: msg} }

// loginError is a gateway's reason for turning a login down. Wrong credentials won't fix
// themselves, so those are refused for good; anything else (a stale one-time code, a limit) is
// an ordinary error, retried after the usual wait.
func loginError(msg string) error {
	for _, word := range []string{"password", "passwd", "user", "密码", "用户", "账号", "帐号", "locked", "锁定", "expired", "过期"} {
		if strings.Contains(strings.ToLower(msg), word) {
			return refused(msg)
		}
	}
	return errors.New(msg)
}

func unsupported(what string) error {
	return refused(fmt.Sprintf("the gateway asks for %s, which is not supported", what))
}

// field is the text of <tag>...</tag>. The gateway's replies are XML-shaped,
// but not reliably enough to hand to a parser.
func field(tag, text string) string {
	open := "<" + tag + ">"
	start := strings.Index(text, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(text[start:], "</"+tag+">")
	if end < 0 {
		return ""
	}
	v := strings.TrimSpace(text[start : start+end])
	if inner, ok := strings.CutPrefix(v, "<![CDATA["); ok { // some gateways wrap values, "<![CDATA[incorrect svpn_req_randcode]]>"
		v = strings.TrimSuffix(inner, "]]>")
	}
	return v
}

func prefix(text string) string {
	if r := []rune(text); len(r) > 200 {
		return string(r[:200])
	}
	return text
}

// totp is RFC 6238: six digits, thirty-second steps, HMAC-SHA1.
func totp(secret string, unix int64) (string, error) {
	clean := strings.ToUpper(strings.NewReplacer("=", "", " ", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", errors.New("the TOTP secret is not base32")
	}
	m := hmac.New(sha1.New, key)
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(unix/30)))
	mac := m.Sum(nil)
	o := mac[19] & 0x0F
	number := binary.BigEndian.Uint32(mac[o:o+4]) & 0x7FFFFFFF % 1_000_000
	return fmt.Sprintf("%06d", number), nil
}
