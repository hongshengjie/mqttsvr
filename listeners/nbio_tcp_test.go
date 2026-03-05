// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 mochi-mqtt, mochi-co

package listeners

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/mochi-mqtt/server/v2/packets"
)

// ─────────────────────────────────────────────────────────────────────────────
// Mock NBioSessionHandler for testing
// ─────────────────────────────────────────────────────────────────────────────

type mockNbioSession struct {
	conn net.Conn
	data [][]byte
	mu   sync.Mutex
}

type mockNbioHandler struct {
	mu       sync.Mutex
	sessions []*mockNbioSession
	opens    int32
	closes   int32
	onOpen   func(id string, conn net.Conn) interface{}
	onData   func(sess interface{}, data []byte) error
	onClose  func(sess interface{}, err error)
}

func (h *mockNbioHandler) OnNbioOpen(id string, conn net.Conn) interface{} {
	atomic.AddInt32(&h.opens, 1)
	if h.onOpen != nil {
		return h.onOpen(id, conn)
	}
	sess := &mockNbioSession{conn: conn}
	h.mu.Lock()
	h.sessions = append(h.sessions, sess)
	h.mu.Unlock()
	return sess
}

func (h *mockNbioHandler) OnNbioData(sess interface{}, data []byte) error {
	if h.onData != nil {
		return h.onData(sess, data)
	}
	s := sess.(*mockNbioSession)
	s.mu.Lock()
	s.data = append(s.data, append([]byte(nil), data...))
	s.mu.Unlock()
	return nil
}

func (h *mockNbioHandler) OnNbioClose(sess interface{}, err error) {
	atomic.AddInt32(&h.closes, 1)
	if h.onClose != nil {
		h.onClose(sess, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PacketParser unit tests
// ─────────────────────────────────────────────────────────────────────────────

// buildConnectPacket creates a minimal MQTT v4 CONNECT packet as raw bytes.
func buildConnectPacket(clientID string) []byte {
	var buf bytes.Buffer
	// Variable header: protocol name + level + flags + keepalive
	// "MQTT" protocol name (length-prefixed)
	buf.Write([]byte{0x00, 0x04, 'M', 'Q', 'T', 'T'})
	buf.WriteByte(0x04) // protocol level 4 (MQTT v3.1.1)
	buf.WriteByte(0x02) // clean session
	buf.Write([]byte{0x00, 0x0a}) // keepalive 10s

	// Payload: client ID (length-prefixed)
	idBytes := []byte(clientID)
	idLen := make([]byte, 2)
	binary.BigEndian.PutUint16(idLen, uint16(len(idBytes)))
	buf.Write(idLen)
	buf.Write(idBytes)

	payload := buf.Bytes()

	// Fixed header: type=CONNECT (0x10), remaining length
	var full bytes.Buffer
	full.WriteByte(0x10)
	// Encode remaining length
	remaining := len(payload)
	for {
		eb := byte(remaining % 128)
		remaining /= 128
		if remaining > 0 {
			eb |= 0x80
		}
		full.WriteByte(eb)
		if remaining == 0 {
			break
		}
	}
	full.Write(payload)
	return full.Bytes()
}

// buildPingreqPacket creates a minimal PINGREQ packet.
func buildPingreqPacket() []byte {
	return []byte{0xC0, 0x00}
}

func TestPacketParserConnectFullPacket(t *testing.T) {
	p := NewPacketParser()
	raw := buildConnectPacket("test-client")
	p.Feed(raw)

	pk, ok, err := p.Next(0)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, packets.Connect, pk.FixedHeader.Type)
	require.Equal(t, "test-client", pk.Connect.ClientIdentifier)
}

func TestPacketParserInsufficientData(t *testing.T) {
	p := NewPacketParser()

	// Only 1 byte — not enough
	p.Feed([]byte{0x10})
	_, ok, err := p.Next(0)
	require.NoError(t, err)
	require.False(t, ok)

	// Add the remaining length byte but no payload
	p.Feed([]byte{0x05}) // remaining=5
	_, ok, err = p.Next(0)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestPacketParserFragmentedDelivery(t *testing.T) {
	p := NewPacketParser()
	raw := buildConnectPacket("frag-client")

	// Feed one byte at a time
	for i, b := range raw {
		p.Feed([]byte{b})
		pk, ok, err := p.Next(0)
		require.NoError(t, err)
		if i < len(raw)-1 {
			require.False(t, ok, "should not parse until all bytes delivered (byte %d)", i)
		} else {
			require.True(t, ok)
			require.Equal(t, "frag-client", pk.Connect.ClientIdentifier)
		}
	}
}

func TestPacketParserMultiplePackets(t *testing.T) {
	p := NewPacketParser()
	// Feed CONNECT followed by PINGREQ in one go
	raw := append(buildConnectPacket("multi-client"), buildPingreqPacket()...)
	p.Feed(raw)

	pk1, ok1, err1 := p.Next(4)
	require.NoError(t, err1)
	require.True(t, ok1)
	require.Equal(t, packets.Connect, pk1.FixedHeader.Type)

	pk2, ok2, err2 := p.Next(4)
	require.NoError(t, err2)
	require.True(t, ok2)
	require.Equal(t, packets.Pingreq, pk2.FixedHeader.Type)

	// No more packets
	_, ok3, err3 := p.Next(4)
	require.NoError(t, err3)
	require.False(t, ok3)
}

func TestPacketParserPingreq(t *testing.T) {
	p := NewPacketParser()
	p.Feed(buildPingreqPacket())

	pk, ok, err := p.Next(4)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, packets.Pingreq, pk.FixedHeader.Type)
}

func TestPacketParserBufferAdvances(t *testing.T) {
	p := NewPacketParser()
	p.Feed(buildConnectPacket("advance"))

	_, ok, err := p.Next(0)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, p.buf, "buffer should be empty after successful parse")
}

// ─────────────────────────────────────────────────────────────────────────────
// NBioTCP listener unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestNewNBioTCP(t *testing.T) {
	cfg := NBioConfig{Config: Config{ID: "nb1", Address: ":0"}}
	l := NewNBioTCP(cfg)
	require.Equal(t, "nb1", l.ID())
	require.Equal(t, "tcp", l.Protocol())
}

func TestNBioTCPProtocol(t *testing.T) {
	plain := NewNBioTCP(NBioConfig{Config: Config{ID: "nb1"}})
	require.Equal(t, "tcp", plain.Protocol())

	tls := NewNBioTCP(NBioConfig{Config: Config{ID: "nb2", TLSConfig: tlsConfigBasic}})
	require.Equal(t, "tcps", tls.Protocol())
}

func TestNBioTCPInit(t *testing.T) {
	l := NewNBioTCP(NBioConfig{Config: Config{ID: "nb1", Address: ":0"}})
	err := l.Init(logger)
	require.NoError(t, err)
}

func TestNBioTCPServeNoHandler(t *testing.T) {
	l := NewNBioTCP(NBioConfig{Config: Config{ID: "nb1", Address: ":0"}})
	_ = l.Init(logger)
	// Should return without hanging (logs an error internally).
	done := make(chan struct{})
	go func() {
		l.Serve(MockEstablisher)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Serve did not return when Handler is nil")
	}
}

func TestNBioTCPSetHandler(t *testing.T) {
	l := NewNBioTCP(NBioConfig{Config: Config{ID: "nb1"}})
	h := &mockNbioHandler{}
	l.SetHandler(h)
	require.Equal(t, h, l.config.Handler)
}

func TestNBioTCPServeAndClose(t *testing.T) {
	h := &mockNbioHandler{}
	cfg := NBioConfig{
		Config:  Config{ID: "nb1", Address: ":0"},
		Handler: h,
	}
	l := NewNBioTCP(cfg)
	_ = l.Init(logger)

	done := make(chan struct{})
	go func() {
		l.Serve(MockEstablisher)
		close(done)
	}()

	// Give the engine a moment to start.
	time.Sleep(50 * time.Millisecond)

	closerCalled := false
	l.Close(func(id string) {
		closerCalled = true
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	require.True(t, closerCalled)
}

func TestNBioTCPAcceptAndReceiveData(t *testing.T) {
	received := make(chan []byte, 16)
	h := &mockNbioHandler{
		onData: func(sess interface{}, data []byte) error {
			received <- append([]byte(nil), data...)
			return nil
		},
	}

	cfg := NBioConfig{
		Config:  Config{ID: "nb1", Address: ":0"},
		Handler: h,
	}
	l := NewNBioTCP(cfg)
	_ = l.Init(logger)

	go l.Serve(MockEstablisher)
	time.Sleep(50 * time.Millisecond)

	addr := l.Address()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	payload := []byte("hello nbio")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	var got []byte
	deadline := time.After(2 * time.Second)
outer:
	for {
		select {
		case chunk := <-received:
			got = append(got, chunk...)
			if bytes.Contains(got, payload) {
				break outer
			}
		case <-deadline:
			t.Fatal("timed out waiting for data")
		}
	}

	require.Contains(t, string(got), string(payload))
	l.Close(MockCloser)
}

func TestNBioTCPRateLimiting(t *testing.T) {
	openCount := int32(0)
	h := &mockNbioHandler{
		onOpen: func(id string, conn net.Conn) interface{} {
			atomic.AddInt32(&openCount, 1)
			return &mockNbioSession{conn: conn}
		},
	}

	cfg := NBioConfig{
		Config:    Config{ID: "nb1", Address: ":0"},
		Handler:   h,
		RateLimit: rate.Limit(1), // 1 connection/s
		RateBurst: 1,
	}
	l := NewNBioTCP(cfg)
	_ = l.Init(logger)

	go l.Serve(MockEstablisher)
	time.Sleep(50 * time.Millisecond)

	addr := l.Address()

	// First connection should be allowed (burst=1 lets the first through).
	conn1, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn1.Close()

	// Wait briefly so the engine processes the first connection.
	time.Sleep(100 * time.Millisecond)

	// Second connection should be rate-limited and dropped.
	conn2, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn2.Close()

	// The second connection should be closed by the server immediately.
	conn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, readErr := conn2.Read(buf)
	require.Error(t, readErr, "rate-limited connection should be closed by server")

	l.Close(MockCloser)
}

func TestNBioTCPCloseIdempotent(t *testing.T) {
	h := &mockNbioHandler{}
	cfg := NBioConfig{Config: Config{ID: "nb1", Address: ":0"}, Handler: h}
	l := NewNBioTCP(cfg)
	_ = l.Init(logger)

	go l.Serve(MockEstablisher)
	time.Sleep(50 * time.Millisecond)

	l.Close(MockCloser)
	l.Close(MockCloser) // second call must not panic
}

func TestNBioTCPOnCloseCalledOnDisconnect(t *testing.T) {
	closes := int32(0)
	h := &mockNbioHandler{
		onClose: func(sess interface{}, err error) {
			atomic.AddInt32(&closes, 1)
		},
	}

	cfg := NBioConfig{Config: Config{ID: "nb1", Address: ":0"}, Handler: h}
	l := NewNBioTCP(cfg)
	_ = l.Init(logger)

	go l.Serve(MockEstablisher)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", l.Address())
	require.NoError(t, err)

	// Wait for OnOpen to be invoked.
	time.Sleep(50 * time.Millisecond)

	conn.Close()

	// Wait for OnClose to fire.
	deadline := time.After(1 * time.Second)
	for {
		if atomic.LoadInt32(&closes) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("OnNbioClose was not called after connection close")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	l.Close(MockCloser)
}

// ─────────────────────────────────────────────────────────────────────────────
// convertStdTLSConfig unit test
// ─────────────────────────────────────────────────────────────────────────────

func TestConvertStdTLSConfigNil(t *testing.T) {
	result := convertStdTLSConfig(nil)
	require.Nil(t, result)
}

func TestConvertStdTLSConfigBasic(t *testing.T) {
	result := convertStdTLSConfig(tlsConfigBasic)
	require.NotNil(t, result)
	require.Equal(t, tlsConfigBasic.MinVersion, result.MinVersion)
	require.Len(t, result.Certificates, len(tlsConfigBasic.Certificates))
}
