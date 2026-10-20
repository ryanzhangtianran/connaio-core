// Package easyconnect speaks the Sangfor EasyConnect protocol: the login, the
// packet tunnel and the TLS underneath both. Ported from Termther's Rust engine
// (EC/). The TCP/IP stack on top of the tunnel is the kernel's own.
package easyconnect

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Just enough TLS to talk to a Sangfor gateway.
//
// The gateway needs two things that no TLS library offers. First, a
// ClientHello with a chosen session ID: "L3IP" and zeros is how the gateway
// tells a tunnel apart from its web portal, which listens on the same port,
// and it only accepts TLS 1.1 with RC4. Second, the session ID the server
// returns on an ordinary handshake, which becomes half of the tunnel token.
//
// RSA key exchange only, with RC4-SHA or AES-CBC-SHA, over TLS 1.1 or 1.2.
// The certificate is not verified, as in every EasyConnect client: campus
// gateways often present certificates that would fail validation.

// ErrClosed is the other end closing the connection.
var ErrClosed = errors.New("connection closed")

const (
	recordChangeCipherSpec = 20
	recordAlert            = 21
	recordHandshake        = 22
	recordApplicationData  = 23

	versionTLS11 = 0x0302
	versionTLS12 = 0x0303

	suiteRC4       = 0x0005
	suiteAES128CBC = 0x002F
	suiteAES256CBC = 0x0035
	suiteSCSV      = 0x00FF
)

// hello is the kind of ClientHello: the tunnel's, or an ordinary one for the portal.
type hello struct {
	tunnel     bool
	serverName string
}

type tlsConn struct {
	raw net.Conn
	// Buffered for reading, so a record is one read rather than two; writes go
	// to the socket underneath.
	r *bufio.Reader
	// The session ID from the ServerHello.
	sessionID []byte
	version   uint16
	reader    *cipherState
	writer    *cipherState
	pending   []byte
	// buf holds the record being read; out collects the records of one write. Both are reused.
	buf []byte
	out []byte
}

func handshake(raw net.Conn, h hello) (*tlsConn, error) {
	c := &tlsConn{raw: raw, r: bufio.NewReaderSize(raw, 32*1024), version: 0x0301}
	if err := c.run(h); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *tlsConn) run(h hello) error {
	clientRandom := random(32)
	var (
		offered   uint16
		sessionID []byte
		suites    []uint16
		ext       []byte
	)
	if h.tunnel {
		offered = versionTLS11
		sessionID = append([]byte("L3IP"), make([]byte, 28)...)
		suites = []uint16{suiteRC4, suiteSCSV}
		// A heartbeat extension. The gateway expects it even though heartbeats are never sent.
		ext = []byte{0x00, 0x0F, 0x00, 0x01, 0x01}
	} else {
		offered = versionTLS12
		// signature_algorithms: rsa_pkcs1_sha256, rsa_pkcs1_sha1.
		ext = []byte{0x00, 0x0D, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x02, 0x01}
		if _, err := netip.ParseAddr(h.serverName); err != nil {
			b := cryptobyte.NewBuilder(ext)
			b.AddUint16(0) // server_name
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0) // host_name
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(h.serverName)) })
				})
			})
			ext = b.BytesOrPanic()
		}
		suites = []uint16{suiteAES128CBC, suiteAES256CBC, suiteRC4, suiteSCSV}
	}

	var b cryptobyte.Builder
	b.AddUint16(offered)
	b.AddBytes(clientRandom)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sessionID) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, s := range suites {
			b.AddUint16(s)
		}
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) }) // compression: null only
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ext) })
	transcript := handshakeMessage(1, b.BytesOrPanic())
	if err := c.writeRecord(recordHandshake, transcript); err != nil {
		return err
	}

	// ServerHello
	_, serverHello, raw, err := c.readHandshake(2)
	if err != nil {
		return err
	}
	transcript = append(transcript, raw...)
	var serverRandom []byte
	var serverSession cryptobyte.String
	var suite uint16
	sh := cryptobyte.String(serverHello)
	if !sh.ReadUint16(&c.version) || !sh.ReadBytes(&serverRandom, 32) || !sh.ReadUint8LengthPrefixed(&serverSession) || !sh.ReadUint16(&suite) {
		return errors.New("TLS: truncated ServerHello")
	}
	if !(c.version == versionTLS11 || c.version == versionTLS12) || c.version > offered {
		return fmt.Errorf("TLS: server chose version %04x", c.version)
	}
	c.sessionID = append([]byte(nil), serverSession...)
	if !slices.Contains(suites, suite) || suite == suiteSCSV {
		return fmt.Errorf("TLS: server chose cipher %04x", suite)
	}

	// Certificate, then ServerHelloDone.
	var certificate []byte
	for {
		kind, body, raw, err := c.readHandshake(0)
		if err != nil {
			return err
		}
		transcript = append(transcript, raw...)
		if kind == 14 {
			break
		}
		switch kind {
		case 11:
			var list, first cryptobyte.String
			if certs := cryptobyte.String(body); !certs.ReadUint24LengthPrefixed(&list) || !list.ReadUint24LengthPrefixed(&first) {
				return errors.New("TLS: malformed Certificate")
			}
			certificate = first
		case 13:
			return errors.New("TLS: gateway asks for a client certificate")
		default:
			return fmt.Errorf("TLS: unexpected handshake message %d", kind)
		}
	}
	key := publicKey(certificate)
	if key == nil {
		return errors.New("TLS: unreadable server certificate")
	}

	// ClientKeyExchange: a premaster secret, encrypted to the certificate.
	premaster := binary.BigEndian.AppendUint16(nil, offered)
	premaster = append(premaster, random(46)...)
	sealed, err := rsa.EncryptPKCS1v15(rand.Reader, key, premaster)
	if err != nil {
		return fmt.Errorf("RSA: %w", err)
	}
	var kx cryptobyte.Builder
	kx.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sealed) })
	exchange := handshakeMessage(16, kx.BytesOrPanic())
	transcript = append(transcript, exchange...)
	if err := c.writeRecord(recordHandshake, exchange); err != nil {
		return err
	}

	master := prf(c.version, premaster, "master secret", append(append([]byte{}, clientRandom...), serverRandom...), 48)
	keyLength := 16
	if suite == suiteAES256CBC {
		keyLength = 32
	}
	block := prf(c.version, master, "key expansion", append(append([]byte{}, serverRandom...), clientRandom...), 40+2*keyLength)
	clientMAC, serverMAC := block[0:20], block[20:40]
	clientKey, serverKey := block[40:40+keyLength], block[40+keyLength:]
	useRC4 := suite == suiteRC4

	if err := c.writeRecord(recordChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	c.writer = newCipherState(clientKey, clientMAC, useRC4)
	finished := handshakeMessage(20, prf(c.version, master, "client finished", c.transcriptHash(transcript), 12))
	transcript = append(transcript, finished...)
	if err := c.writeRecord(recordHandshake, finished); err != nil {
		return err
	}

	kind, _, err := c.readRecord()
	if err != nil {
		return err
	}
	if kind != recordChangeCipherSpec {
		return fmt.Errorf("TLS: expected ChangeCipherSpec, got %d", kind)
	}
	c.reader = newCipherState(serverKey, serverMAC, useRC4)
	_, serverFinished, _, err := c.readHandshake(20)
	if err != nil {
		return err
	}
	if !hmac.Equal(serverFinished, prf(c.version, master, "server finished", c.transcriptHash(transcript), 12)) {
		return errors.New("TLS: server Finished does not verify")
	}
	return nil
}

// Write sends bytes as application data, in as few records as possible.
func (c *tlsConn) Write(b []byte) error {
	return c.WriteEach([][]byte{b})
}

// WriteEach sends each message as application data in records of its own, all
// in one write. The tunnel needs one packet per record.
func (c *tlsConn) WriteEach(messages [][]byte) error {
	records := c.out[:0]
	for _, m := range messages {
		for len(m) > 0 {
			n := min(len(m), 16384)
			records = c.appendRecord(recordApplicationData, m[:n], records)
			m = m[n:]
		}
	}
	c.out = records[:0]
	_, err := c.raw.Write(records)
	return closedOr(err)
}

// Read returns the payload of the next application-data record. The tunnel
// sends one IP packet per record, so record boundaries matter. The slice is
// reused by the next Read: copy what must outlive it.
func (c *tlsConn) Read() ([]byte, error) {
	for {
		kind, payload, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if kind == recordApplicationData {
			return payload, nil
		}
		// Anything else after the handshake, such as a HelloRequest, is ignored.
	}
}

func (c *tlsConn) Close() error                       { return c.raw.Close() }
func (c *tlsConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *tlsConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *tlsConn) writeRecord(kind byte, payload []byte) error {
	_, err := c.raw.Write(c.appendRecord(kind, payload, nil))
	return closedOr(err)
}

// appendRecord puts one record onto the end of out, sealed in place.
func (c *tlsConn) appendRecord(kind byte, payload []byte, out []byte) []byte {
	start := len(out)
	out = append(out, kind)
	out = binary.BigEndian.AppendUint16(out, c.version)
	out = append(out, 0, 0)
	if c.writer != nil {
		out = c.writer.seal(kind, c.version, payload, out)
	} else {
		out = append(out, payload...)
	}
	binary.BigEndian.PutUint16(out[start+3:], uint16(len(out)-start-5))
	return out
}

func (c *tlsConn) readRecord() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.r, header[:]); err != nil {
		return 0, nil, closedOr(err)
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if length > 18432 {
		return 0, nil, errors.New("TLS: oversized record")
	}
	if cap(c.buf) < length {
		c.buf = make([]byte, 18432)
	}
	payload := c.buf[:length]
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return 0, nil, closedOr(err)
	}
	if c.reader != nil {
		var err error
		if payload, err = c.reader.open(header[0], c.version, payload); err != nil {
			return 0, nil, err
		}
	}
	if header[0] == recordAlert && len(payload) == 2 {
		if payload[1] == 0 {
			return 0, nil, ErrClosed
		}
		return 0, nil, fmt.Errorf("TLS alert %d", payload[1])
	}
	return header[0], payload, nil
}

// readHandshake returns (type, body, the whole message as it goes into the
// transcript). expected 0 accepts any type.
func (c *tlsConn) readHandshake(expected byte) (byte, []byte, []byte, error) {
	for {
		if len(c.pending) >= 4 {
			length := int(c.pending[1])<<16 | int(c.pending[2])<<8 | int(c.pending[3])
			if len(c.pending) >= 4+length {
				raw := append([]byte(nil), c.pending[:4+length]...)
				c.pending = c.pending[4+length:]
				if expected != 0 && raw[0] != expected {
					return 0, nil, nil, fmt.Errorf("TLS: expected handshake message %d, got %d", expected, raw[0])
				}
				return raw[0], raw[4:], raw, nil
			}
		}
		kind, payload, err := c.readRecord()
		if err != nil {
			return 0, nil, nil, err
		}
		if kind != recordHandshake {
			return 0, nil, nil, fmt.Errorf("TLS: expected handshake, got record %d", kind)
		}
		c.pending = append(c.pending, payload...)
	}
}

func (c *tlsConn) transcriptHash(transcript []byte) []byte {
	if c.version >= versionTLS12 {
		sum := sha256.Sum256(transcript)
		return sum[:]
	}
	m, s := md5.Sum(transcript), sha1.Sum(transcript)
	return append(m[:], s[:]...)
}

// prf is the TLS pseudorandom function: P_SHA256 for 1.2, P_MD5 XOR P_SHA1 before it.
func prf(version uint16, secret []byte, label string, seed []byte, count int) []byte {
	seed = append([]byte(label), seed...)
	if version >= versionTLS12 {
		return pHash(sha256.New, secret, seed, count)
	}
	half := (len(secret) + 1) / 2
	out := pHash(md5.New, secret[:half], seed, count)
	for i, b := range pHash(sha1.New, secret[len(secret)-half:], seed, count) {
		out[i] ^= b
	}
	return out
}

func pHash(h func() hash.Hash, secret, seed []byte, count int) []byte {
	mac := func(data ...[]byte) []byte {
		m := hmac.New(h, secret)
		for _, d := range data {
			m.Write(d)
		}
		return m.Sum(nil)
	}
	var out []byte
	a := seed
	for len(out) < count {
		a = mac(a)
		out = append(out, mac(a, seed)...)
	}
	return out[:count]
}

// publicKey is the RSA key of a DER certificate, found by walking the fields
// that precede the SubjectPublicKeyInfo rather than parsing the whole thing:
// campus certificates are not always ones crypto/x509 accepts.
func publicKey(certificate []byte) *rsa.PublicKey {
	var cert, tbs, skip, spki cryptobyte.String
	var tag asn1.Tag
	s := cryptobyte.String(certificate)
	if !s.ReadASN1(&cert, asn1.SEQUENCE) || !cert.ReadASN1(&tbs, asn1.SEQUENCE) || !tbs.SkipOptionalASN1(asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil
	}
	for i := 0; i < 5; i++ { // serial, signature, issuer, validity, subject
		if !tbs.ReadAnyASN1(&skip, &tag) {
			return nil
		}
	}
	if !tbs.ReadASN1Element(&spki, asn1.SEQUENCE) {
		return nil
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil
	}
	rsaKey, _ := key.(*rsa.PublicKey)
	return rsaKey
}

// cipherState is record protection for one direction: RC4 or AES-CBC, each with HMAC-SHA1.
type cipherState struct {
	block cipher.Block
	// mac is keyed once and reset per record; sum is where its tag lands.
	mac      hash.Hash
	sum      [20]byte
	rc4      *rc4.Cipher
	sequence uint64
}

func newCipherState(key, macKey []byte, useRC4 bool) *cipherState {
	s := &cipherState{mac: hmac.New(sha1.New, macKey)}
	if useRC4 {
		s.rc4, _ = rc4.NewCipher(key)
	} else {
		s.block, _ = aes.NewCipher(key)
	}
	return s
}

// tag is the record MAC, valid until the next call.
func (s *cipherState) tag(kind byte, version uint16, content []byte) []byte {
	var header [13]byte
	binary.BigEndian.PutUint64(header[:], s.sequence)
	header[8] = kind
	binary.BigEndian.PutUint16(header[9:], version)
	binary.BigEndian.PutUint16(header[11:], uint16(len(content)))
	s.mac.Reset()
	s.mac.Write(header[:])
	s.mac.Write(content)
	return s.mac.Sum(s.sum[:0])
}

// seal appends the sealed body of a record to out, encrypted in place there.
func (s *cipherState) seal(kind byte, version uint16, plain, out []byte) []byte {
	tag := s.tag(kind, version, plain)
	s.sequence++
	if s.rc4 != nil {
		start := len(out)
		out = append(out, plain...)
		out = append(out, tag...)
		s.rc4.XORKeyStream(out[start:], out[start:])
		return out
	}
	iv := random(16)
	out = append(out, iv...)
	start := len(out)
	out = append(out, plain...)
	out = append(out, tag...)
	pad := 15 - (len(out)-start)%16
	for i := 0; i <= pad; i++ {
		out = append(out, byte(pad))
	}
	cipher.NewCBCEncrypter(s.block, iv).CryptBlocks(out[start:], out[start:])
	return out
}

// open unseals a record in place, returning the plaintext.
func (s *cipherState) open(kind byte, version uint16, record []byte) ([]byte, error) {
	if s.rc4 != nil {
		s.rc4.XORKeyStream(record, record)
	} else {
		if len(record) < 32 || len(record)%16 != 0 {
			return nil, errors.New("TLS: malformed CBC record")
		}
		cipher.NewCBCDecrypter(s.block, record[:16]).CryptBlocks(record[16:], record[16:])
		record = record[16:]
		pad := int(record[len(record)-1])
		if pad+21 > len(record) {
			return nil, errors.New("TLS: bad padding")
		}
		record = record[:len(record)-pad-1]
	}
	if len(record) < 20 {
		return nil, errors.New("TLS: short record")
	}
	length := len(record) - 20
	if !hmac.Equal(record[length:], s.tag(kind, version, record[:length])) {
		return nil, errors.New("TLS: bad record MAC")
	}
	s.sequence++
	return record[:length], nil
}

func handshakeMessage(kind byte, body []byte) []byte {
	return append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func closedOr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrClosed
	}
	return err
}
