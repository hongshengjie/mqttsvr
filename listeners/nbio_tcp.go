// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 mochi-mqtt, mochi-co

// Package listeners provides event-driven TCP listener support via lesismal/nbio.
// NBioTCP eliminates per-connection goroutines by using an epoll/kqueue-based
// event loop with a shared goroutine pool. Connection rate limiting is applied
// before any TLS handshake starts.
package listeners

import (
	"bytes"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	libtls "github.com/lesismal/llib/std/crypto/tls"
	"github.com/lesismal/nbio"
	"github.com/lesismal/nbio/mempool"
	"golang.org/x/time/rate"
	"log/slog"

	"github.com/mochi-mqtt/server/v2/packets"
)

const TypeNBioTCP = "nbio_tcp"

// NBioSessionHandler is implemented by the MQTT server to handle nbio
// connection lifecycle events without per-connection goroutines.
type NBioSessionHandler interface {
	// OnNbioOpen is called when a new connection is ready for MQTT traffic
	// (after rate limiting and, for TLS, after the handshake completes).
	// conn is the net.Conn for this connection (nbio.Conn or *libtls.Conn).
	// Returns an opaque session token that is passed to OnNbioData/OnNbioClose.
	OnNbioOpen(listenerID string, conn net.Conn) interface{}

	// OnNbioData is called when decrypted data arrives on a connection.
	// session is the value previously returned by OnNbioOpen.
	OnNbioData(session interface{}, data []byte) error

	// OnNbioClose is called when a connection closes (cleanly or with error).
	// session is the value previously returned by OnNbioOpen.
	OnNbioClose(session interface{}, err error)
}

// NBioConfig extends the standard Config with event-driven settings.
type NBioConfig struct {
	Config

	// RateLimit is the maximum number of new connections per second.
	// 0 means unlimited.
	RateLimit rate.Limit

	// RateBurst is the burst allowance for the rate limiter.
	// Defaults to int(RateLimit) when 0 and RateLimit > 0.
	RateBurst int

	// NPoller is the number of nbio poller goroutines.
	// 0 uses the nbio default (usually the number of CPUs).
	NPoller int

	// LibTLSConfig is the lesismal/llib TLS configuration for non-blocking TLS.
	// When nil and Config.TLSConfig is non-nil, a basic field conversion is
	// attempted. For full control (e.g. GetCertificate callback), set this directly.
	LibTLSConfig *libtls.Config

	// Handler is the MQTT server's event handler. Set automatically by
	// server.AddListener when an *NBioTCP is added to the server.
	Handler NBioSessionHandler
}

// nbioTLSSession stores per-connection state for a TLS-wrapped nbio connection.
// For plain TCP, the mqttSession is stored directly in nbio.Conn.Session().
type nbioTLSSession struct {
	tlsConn     *libtls.Conn
	mqttSession interface{} // lazily set on first decrypted byte (after TLS handshake)
}

// NBioTCP is an event-driven TCP listener that uses lesismal/nbio.
// Reading is multiplexed via epoll/kqueue with a shared goroutine pool —
// no per-connection read goroutine. Writing is also goroutine-free because
// nbio.Conn.Write buffers data asynchronously (non-blocking).
type NBioTCP struct {
	mu      sync.Mutex
	id      string
	address string
	config  NBioConfig
	engine  *nbio.Engine
	log     *slog.Logger
	limiter *rate.Limiter
	done    chan struct{}
	end     uint32
}

// SetHandler sets the NBioSessionHandler for event-driven packet processing.
// Called automatically by server.AddListener.
func (l *NBioTCP) SetHandler(h NBioSessionHandler) {
	l.config.Handler = h
}

// NBioConfig returns the listener's configuration (for testing/inspection).
func (l *NBioTCP) NBioConfig() NBioConfig {
	return l.config
}

// NewNBioTCP creates and returns a new NBioTCP listener.
func NewNBioTCP(config NBioConfig) *NBioTCP {
	l := &NBioTCP{
		id:      config.ID,
		address: config.Address,
		config:  config,
		done:    make(chan struct{}),
	}

	if config.RateLimit > 0 {
		burst := config.RateBurst
		if burst <= 0 {
			burst = int(config.RateLimit)
		}
		l.limiter = rate.NewLimiter(config.RateLimit, burst)
	}

	return l
}

// ID returns the listener id.
func (l *NBioTCP) ID() string { return l.id }

// Address returns the listener address. After Start, it reflects the actual bound address.
func (l *NBioTCP) Address() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.engine != nil && len(l.engine.Addrs) > 0 {
		return l.engine.Addrs[0]
	}
	return l.address
}

// Protocol returns "tcp" for plain or "tcps" for TLS.
func (l *NBioTCP) Protocol() string {
	if l.config.TLSConfig != nil || l.config.LibTLSConfig != nil {
		return "tcps"
	}
	return "tcp"
}

// Init initializes the listener (stores the logger).
func (l *NBioTCP) Init(log *slog.Logger) error {
	l.log = log
	return nil
}

// Serve starts the nbio event engine and blocks until Close is called.
// The establish parameter is present for interface compatibility but is unused;
// the server must call server.AddListener (which sets NBioConfig.Handler) before
// calling Serve. If Handler is nil this method logs an error and returns.
func (l *NBioTCP) Serve(establish EstablishFn) {
	if atomic.LoadUint32(&l.end) == 1 {
		return
	}

	handler := l.config.Handler
	if handler == nil {
		l.log.Error("NBioTCP: Handler not set; was server.AddListener called?",
			"listener", l.id)
		return
	}

	// Resolve TLS config: prefer LibTLSConfig, fall back to converting TLSConfig.
	tlsCfg := l.config.LibTLSConfig
	if tlsCfg == nil && l.config.TLSConfig != nil {
		tlsCfg = convertStdTLSConfig(l.config.TLSConfig)
	}

	conf := nbio.Config{
		Name:    l.id,
		Network: "tcp",
		Addrs:   []string{l.address},
		NPoller: l.config.NPoller,
	}

	engine := nbio.NewEngine(conf)
	l.setupCallbacks(engine, handler, tlsCfg)

	if err := engine.Start(); err != nil {
		l.log.Error("NBioTCP engine start failed", "listener", l.id, "error", err)
		return
	}

	l.mu.Lock()
	l.engine = engine
	l.mu.Unlock()

	// Block until Close() signals done.
	<-l.done
	engine.Stop()
}

// Close stops the listener and triggers the server's client cleanup callback.
func (l *NBioTCP) Close(closeClients CloseFn) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if atomic.CompareAndSwapUint32(&l.end, 0, 1) {
		closeClients(l.id)
		select {
		case <-l.done: // already closed
		default:
			close(l.done)
		}
	}
}

// setupCallbacks installs the appropriate OnOpen/OnData/OnClose callbacks on
// the nbio engine depending on whether TLS is requested.
func (l *NBioTCP) setupCallbacks(engine *nbio.Engine, handler NBioSessionHandler, tlsCfg *libtls.Config) {
	if tlsCfg != nil {
		l.setupTLSCallbacks(engine, handler, tlsCfg)
	} else {
		l.setupPlainCallbacks(engine, handler)
	}
}

// setupPlainCallbacks configures the engine for plain (non-TLS) TCP.
// Rate limiting happens in OnOpen before any MQTT data is exchanged.
func (l *NBioTCP) setupPlainCallbacks(engine *nbio.Engine, handler NBioSessionHandler) {
	engine.OnOpen(func(c *nbio.Conn) {
		if l.limiter != nil && !l.limiter.Allow() {
			_ = c.Close()
			return
		}
		sess := handler.OnNbioOpen(l.id, c)
		c.SetSession(sess)
	})

	engine.OnData(func(c *nbio.Conn, data []byte) {
		sess := c.Session()
		if sess == nil {
			_ = c.Close()
			return
		}
		if err := handler.OnNbioData(sess, data); err != nil {
			l.log.Warn("NBioTCP: closing connection", "listener", l.id, "remote", c.RemoteAddr(), "error", err)
			_ = c.Close()
		}
	})

	engine.OnClose(func(c *nbio.Conn, err error) {
		if sess := c.Session(); sess != nil {
			handler.OnNbioClose(sess, err)
		}
	})
}

// setupTLSCallbacks configures the engine for TLS using lesismal/llib non-blocking
// TLS. Rate limiting happens in OnOpen, before the TLS handshake begins.
func (l *NBioTCP) setupTLSCallbacks(engine *nbio.Engine, handler NBioSessionHandler, tlsCfg *libtls.Config) {
	engine.OnOpen(func(c *nbio.Conn) {
		// Rate limit BEFORE the TLS handshake.
		if l.limiter != nil && !l.limiter.Allow() {
			_ = c.Close()
			return
		}
		// Non-blocking server-side TLS conn (lazy=true: handshake on first I/O).
		tlsConn := libtls.NewConn(c, tlsCfg, false, true, mempool.DefaultMemPool)
		c.SetSession(&nbioTLSSession{tlsConn: tlsConn})
	})

	engine.OnData(func(c *nbio.Conn, data []byte) {
		ts, ok := c.Session().(*nbioTLSSession)
		if !ok {
			_ = c.Close()
			return
		}
		// Feed raw (encrypted) bytes into the non-blocking TLS engine.
		if _, err := ts.tlsConn.Append(data); err != nil {
			_ = c.Close()
			return
		}
		// Drain all available decrypted records.
		buf := make([]byte, 4096)
		for {
			n, err := ts.tlsConn.Read(buf)
			if n > 0 {
				// Lazily create the MQTT session on first decrypted byte —
				// this is effectively post-handshake.
				if ts.mqttSession == nil {
					ts.mqttSession = handler.OnNbioOpen(l.id, ts.tlsConn)
					if ts.mqttSession == nil {
						_ = c.Close()
						return
					}
				}
				if herr := handler.OnNbioData(ts.mqttSession, buf[:n]); herr != nil {
					_ = c.Close()
					return
				}
			}
			if err != nil || n == 0 {
				// n==0 with err==nil means non-blocking TLS needs more data.
				break
			}
		}
	})

	engine.OnClose(func(c *nbio.Conn, err error) {
		ts, ok := c.Session().(*nbioTLSSession)
		// If mqttSession is nil the MQTT layer was never initialised
		// (rate-limited or handshake never completed), so skip cleanup.
		if !ok || ts.mqttSession == nil {
			return
		}
		handler.OnNbioClose(ts.mqttSession, err)
	})
}

// convertStdTLSConfig converts a standard *crypto/tls.Config to *libtls.Config
// by copying the commonly used fields. Function-valued fields such as
// GetCertificate are not converted; set NBioConfig.LibTLSConfig directly if
// you need them.
func convertStdTLSConfig(std *stdtls.Config) *libtls.Config {
	if std == nil {
		return nil
	}
	lib := &libtls.Config{
		ServerName:         std.ServerName,
		InsecureSkipVerify: std.InsecureSkipVerify,
		MinVersion:         std.MinVersion,
		MaxVersion:         std.MaxVersion,
		ClientCAs:          std.ClientCAs,
		RootCAs:            std.RootCAs,
		ClientAuth:         libtls.ClientAuthType(std.ClientAuth),
		CipherSuites:       std.CipherSuites,
	}
	for _, c := range std.Certificates {
		lc := libtls.Certificate{
			Certificate:                 c.Certificate,
			PrivateKey:                  c.PrivateKey,
			OCSPStaple:                  c.OCSPStaple,
			SignedCertificateTimestamps: c.SignedCertificateTimestamps,
			Leaf:                        c.Leaf,
		}
		for _, ss := range c.SupportedSignatureAlgorithms {
			lc.SupportedSignatureAlgorithms = append(
				lc.SupportedSignatureAlgorithms,
				libtls.SignatureScheme(ss),
			)
		}
		lib.Certificates = append(lib.Certificates, lc)
	}
	return lib
}

// ─────────────────────────────────────────────────────────────────────────────
// PacketParser — stateful, non-blocking MQTT packet parser (exported for server)
// ─────────────────────────────────────────────────────────────────────────────

// PacketParser accumulates raw bytes and extracts complete MQTT packets without
// blocking. It is NOT safe for concurrent use; callers must serialise access
// (nbio guarantees OnData callbacks for a single connection are sequential).
type PacketParser struct {
	buf []byte
}

// NewPacketParser returns a new PacketParser.
func NewPacketParser() *PacketParser { return &PacketParser{} }

// Feed appends incoming bytes to the internal buffer.
func (p *PacketParser) Feed(data []byte) {
	p.buf = append(p.buf, data...)
}

// Next attempts to extract the next complete MQTT packet from the buffer.
//
//   - (pk, true,  nil)  — packet successfully parsed, buffer advanced.
//   - (_, false,  nil)  — not enough data yet; call Feed then try again.
//   - (_, false,  err)  — malformed data; caller should close the connection.
func (p *PacketParser) Next(protocolVersion byte) (packets.Packet, bool, error) {
	if len(p.buf) < 2 {
		return packets.Packet{}, false, nil
	}

	// ── Fixed header (1 byte) ──────────────────────────────────────────────
	fh := new(packets.FixedHeader)
	if err := fh.Decode(p.buf[0]); err != nil {
		return packets.Packet{}, false, err
	}

	// ── Remaining-length varint (1–4 bytes) ───────────────────────────────
	r := bytes.NewReader(p.buf[1:])
	rlen, rlenBytes, err := packets.DecodeLength(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return packets.Packet{}, false, nil // need more data
		}
		return packets.Packet{}, false, err
	}
	fh.Remaining = rlen

	// ── Full-packet availability check ────────────────────────────────────
	total := 1 + rlenBytes + rlen
	if len(p.buf) < total {
		return packets.Packet{}, false, nil // need more data
	}

	payload := p.buf[1+rlenBytes : total]
	p.buf = append([]byte(nil), p.buf[total:]...) // advance + independent copy

	// ── Decode packet body ────────────────────────────────────────────────
	pk := packets.Packet{ProtocolVersion: protocolVersion, FixedHeader: *fh}
	px := append([]byte(nil), payload...) // independent copy

	switch fh.Type {
	case packets.Connect:
		err = pk.ConnectDecode(px)
	case packets.Disconnect:
		err = pk.DisconnectDecode(px)
	case packets.Connack:
		err = pk.ConnackDecode(px)
	case packets.Publish:
		err = pk.PublishDecode(px)
	case packets.Puback:
		err = pk.PubackDecode(px)
	case packets.Pubrec:
		err = pk.PubrecDecode(px)
	case packets.Pubrel:
		err = pk.PubrelDecode(px)
	case packets.Pubcomp:
		err = pk.PubcompDecode(px)
	case packets.Subscribe:
		err = pk.SubscribeDecode(px)
	case packets.Suback:
		err = pk.SubackDecode(px)
	case packets.Unsubscribe:
		err = pk.UnsubscribeDecode(px)
	case packets.Unsuback:
		err = pk.UnsubackDecode(px)
	case packets.Pingreq, packets.Pingresp:
		// no payload
	case packets.Auth:
		err = pk.AuthDecode(px)
	default:
		return packets.Packet{}, false, fmt.Errorf("%w: %v", packets.ErrNoValidPacketAvailable, fh.Type)
	}

	if err != nil {
		return packets.Packet{}, false, err
	}
	return pk, true, nil
}
