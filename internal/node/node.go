package node

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/mkushnir885/software-security-rgr/conn"
	"github.com/mkushnir885/software-security-rgr/internal/ca"
	"github.com/mkushnir885/software-security-rgr/internal/handshake"
)

type broadcastMsg struct {
	Seq  int    `json:"seq"`
	From string `json:"from"`
	Text string `json:"text"`
}

type Node struct {
	id        int
	privKey   *rsa.PrivateKey
	certDER   []byte
	caCertDER []byte
	log       *slog.Logger

	// sendPeers holds outbound (client-side) connections used for sending.
	// Receive loops run on inbound connections accepted by the listener.
	sendPeers map[string]*conn.SecureConn
	lastSeq   map[string]int // highest seq seen per originator
	seq       int
	mu        sync.RWMutex
}

func New(id int, privKey *rsa.PrivateKey, certDER []byte, caCertDER []byte, log *slog.Logger) *Node {
	return &Node{
		id:        id,
		privKey:   privKey,
		certDER:   certDER,
		caCertDER: caCertDER,
		log:       log,
		sendPeers: make(map[string]*conn.SecureConn),
		lastSeq:   make(map[string]int),
	}
}

func (n *Node) Port() int {
	return 9000 + n.id
}

// Listen starts the node's TCP listener and signals on listenerReady when ready.
func (n *Node) Listen(listenerReady chan<- struct{}) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", n.Port()))
	if err != nil {
		return err
	}
	listenerReady <- struct{}{}
	go func() {
		defer ln.Close()
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go n.handleIncoming(rawConn)
		}
	}()
	return nil
}

func (n *Node) handleIncoming(rawConn net.Conn) {
	c := conn.New(rawConn, "", n.log)
	peerName, sc, err := handshake.Accept(c, n.privKey, n.certDER)
	if err != nil {
		n.log.Error("handshake failed", "err", err)
		rawConn.Close()
		return
	}
	n.log.Info("peer connected", "peer", peerName, "role", "server")
	go n.receiveLoop(peerName, sc)
}

// Dial connects to a peer node and stores the secure connection in sendPeers.
// The receive path for this peer runs via handleIncoming when the peer dials back.
func (n *Node) Dial(peerID int) error {
	rawConn, err := net.Dial("tcp", fmt.Sprintf(":%d", 9000+peerID))
	if err != nil {
		return err
	}
	nodeName := fmt.Sprintf("node%d", n.id)
	caCertDER := n.caCertDER
	c := conn.New(rawConn, fmt.Sprintf("node%d", peerID), n.log)
	peerName, sc, err := handshake.Initiate(c, nodeName, func(certDER []byte) error {
		return ca.VerifyCert(certDER, caCertDER, nodeName, c.Log)
	})
	if err != nil {
		rawConn.Close()
		return err
	}
	n.log.Info("peer connected", "peer", peerName, "role", "client")
	n.mu.Lock()
	n.sendPeers[peerName] = sc
	n.mu.Unlock()
	return nil
}

func (n *Node) receiveLoop(peerName string, sc *conn.SecureConn) {
	for {
		data, err := sc.Receive()
		if err != nil {
			n.log.Info("peer disconnected", "peer", peerName)
			return
		}
		var bm broadcastMsg
		if err := json.Unmarshal(data, &bm); err != nil {
			n.log.Error("unmarshal", "err", err)
			continue
		}
		n.mu.Lock()
		duplicate := bm.Seq <= n.lastSeq[bm.From]
		if !duplicate {
			n.lastSeq[bm.From] = bm.Seq
		}
		n.mu.Unlock()
		if duplicate {
			n.log.Debug("drop duplicate", "from", bm.From, "seq", bm.Seq)
			continue
		}
		n.log.Info("recv", "from", bm.From, "text", bm.Text, "size", len(data))
		n.forward(&bm, peerName)
	}
}

// Broadcast sends a message originating from this node to all sendPeers.
func (n *Node) Broadcast(text string) {
	myName := fmt.Sprintf("node%d", n.id)
	n.mu.Lock()
	n.seq++
	seq := n.seq
	n.lastSeq[myName] = seq // pre-register to suppress any echo
	n.mu.Unlock()
	n.log.Info("broadcast", "text", text)
	n.forward(&broadcastMsg{Seq: seq, From: myName, Text: text}, "")
}

// forward sends bm to all sendPeers except exceptPeer.
func (n *Node) forward(bm *broadcastMsg, exceptPeer string) {
	data, _ := json.Marshal(bm)
	n.mu.RLock()
	defer n.mu.RUnlock()
	for peerName, sc := range n.sendPeers {
		if peerName == exceptPeer {
			continue
		}
		n.log.Info("send", "to", peerName, "size", len(data))
		if err := sc.Send(data); err != nil {
			n.log.Error("send failed", "to", peerName, "err", err)
		}
	}
}
