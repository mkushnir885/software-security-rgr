package ca

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"

	"github.com/mkushnir885/software-security-rgr/conn"
	"github.com/mkushnir885/software-security-rgr/internal/handshake"
)

const ServerPort = 9000

// Server listens for certificate verification requests from nodes.
type Server struct {
	ca  *CA
	log *slog.Logger
}

func NewServer(ca *CA, log *slog.Logger) *Server {
	return &Server{ca: ca, log: log}
}

func (s *Server) Start(ready chan<- struct{}) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", ServerPort))
	if err != nil {
		return err
	}
	s.log.Info("listening", "port", ServerPort)
	ready <- struct{}{}
	go func() {
		defer ln.Close()
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(rawConn)
		}
	}()
	return nil
}

func (s *Server) handleConn(rawConn net.Conn) {
	defer rawConn.Close()
	c := conn.New(rawConn, "", s.log)
	_, sc, err := handshake.Accept(c, s.ca.privKey, s.ca.cert.Raw)
	if err != nil {
		s.log.Error("handshake failed", "err", err)
		return
	}
	certDER, err := sc.Receive()
	if err != nil {
		s.log.Error("recv cert", "from", c.Peer, "err", err)
		return
	}
	s.log.Debug("verify request", "from", c.Peer, "cert_bytes", len(certDER))
	resp := []byte("OK")
	if err := s.ca.Verify(certDER); err != nil {
		s.log.Debug("verification failed", "from", c.Peer, "err", err)
		resp = []byte("ERR: " + err.Error())
	} else {
		s.log.Debug("verification ok", "from", c.Peer)
	}
	if err := sc.Send(resp); err != nil {
		s.log.Error("send response", "to", c.Peer, "err", err)
	}
}

// VerifyCert dials the CA server, performs a secure handshake (verifying the CA cert
// locally against caCertDER), then requests verification of peerCertDER.
func VerifyCert(peerCertDER, caCertDER []byte, nodeName string, log *slog.Logger) error {
	rawConn, err := net.Dial("tcp", fmt.Sprintf(":%d", ServerPort))
	if err != nil {
		return fmt.Errorf("connect to CA: %w", err)
	}
	defer rawConn.Close()
	c := conn.New(rawConn, "nodeCA", log)
	_, sc, err := handshake.Initiate(c, nodeName, func(certDER []byte) error {
		if !bytes.Equal(certDER, caCertDER) {
			return fmt.Errorf("CA cert mismatch")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("CA handshake: %w", err)
	}
	if err := sc.Send(peerCertDER); err != nil {
		return fmt.Errorf("send cert: %w", err)
	}
	resp, err := sc.Receive()
	if err != nil {
		return fmt.Errorf("recv CA response: %w", err)
	}
	if string(resp) != "OK" {
		return fmt.Errorf("%s", string(resp))
	}
	return nil
}
