package pfilter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
)

const quicSize = 5 << 20

func BenchmarkQuic(b *testing.B) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()
	writer, reader := wrapQuic(server)

	benchmark(b, writer, reader, quicSize)
}

func BenchmarkQuicPfilter(b *testing.B) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	pfilter := NewPacketFilter(server)
	pfilterServer := pfilter.NewConn(10, nil)
	pfilter.Start()

	quicServer := &wrapperConn{
		PacketConn: pfilterServer,
		underlying: server.(*net.UDPConn),
	}

	writer, reader := wrapQuic(quicServer)

	benchmark(b, writer, reader, quicSize)
}

func wrapQuic(server net.PacketConn) (quic.Stream, quic.Stream) {
	tlsCfg := &tls.Config{
		// TLS 1.3 is the minimum we accept
		MinVersion: tls.VersionTLS13,
	}
	cert, err := cert()
	if err != nil {
		panic(err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	tlsCfg.NextProtos = []string{"bench"}
	tlsCfg.ClientAuth = tls.RequestClientCert
	tlsCfg.SessionTicketsDisabled = true
	tlsCfg.InsecureSkipVerify = true

	qcfg := &quic.Config{
		ConnectionIDLength: 4,
		KeepAlive:          true,
	}

	l, err := quic.Listen(server, tlsCfg, qcfg)

	cses, err := quic.DialAddr(l.Addr().String(), tlsCfg, qcfg)
	if err != nil {
		panic(err)
	}

	cstrm, err := cses.OpenStream()
	if err != nil {
		panic(err)
	}

	sses, err := l.Accept(context.TODO())
	if err != nil {
		panic(err)
	}

	data := []byte("hello")
	if _, err := cstrm.Write(data); err != nil {
		panic(err)
	}

	sstrm, err := sses.AcceptStream(context.TODO())
	if err != nil {
		panic(err)
	}

	if _, err := sstrm.Read(data); err != nil {
		panic(err)
	}

	return cstrm, sstrm
}

func cert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "generate key")
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(1),
		Subject: pkix.Name{
			CommonName:         "test",
			Organization:       []string{"test"},
			OrganizationalUnit: []string{"Automatically Generated"},
		},
		DNSNames:              []string{"test"},
		NotBefore:             time.Now().Truncate(time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "create cert")
	}

	var certOut bytes.Buffer
	err = pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "save cert")
	}

	var keyOut bytes.Buffer

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "marshal key")
	}
	err = pem.Encode(&keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "save key")
	}

	return tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
}

type wrapperConn struct {
	net.PacketConn
	underlying *net.UDPConn
}

func (s *wrapperConn) SetReadBuffer(size int) error {
	return s.underlying.SetReadBuffer(size)
}

func (s *wrapperConn) SyscallConn() (syscall.RawConn, error) {
	return s.underlying.SyscallConn()
}
