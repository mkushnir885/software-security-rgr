package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"

	"github.com/mkushnir885/software-security-rgr/internal/ca"
	"github.com/mkushnir885/software-security-rgr/internal/node"
	"github.com/mkushnir885/software-security-rgr/logger"
)

// Double Star topology: node1 and node2 are hubs; nodes 3-5 are leaves of node1; nodes 6-8 are leaves of node2.
//
//	3  4  5       6  7  8
//	 \ | /         \ | /
//	  [1] --------- [2]
//
// For each edge both nodes dial each other (duplex): client dials server, then server dials client.
var edges = [][2]int{{1, 2}, {1, 3}, {1, 4}, {1, 5}, {2, 6}, {2, 7}, {2, 8}}

func main() {
	rootCA, err := ca.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ca init:", err)
		os.Exit(1)
	}

	caServer := ca.NewServer(rootCA, logger.NewCALogger())
	caReady := make(chan struct{}, 1)
	if err := caServer.Start(caReady); err != nil {
		fmt.Fprintln(os.Stderr, "ca server:", err)
		os.Exit(1)
	}
	<-caReady
	fmt.Println("nodeCA ready")

	caCertDER := rootCA.CertDER()

	nodes := make(map[int]*node.Node, 8)
	for id := 1; id <= 8; id++ {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "keygen node%d: %v\n", id, err)
			os.Exit(1)
		}
		certDER, err := rootCA.IssueNodeCert(&privKey.PublicKey, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "issue cert node%d: %v\n", id, err)
			os.Exit(1)
		}
		nodes[id] = node.New(id, privKey, certDER, caCertDER, logger.NewNodeLogger(id))
	}

	listenerReady := make(chan struct{}, 8)
	for id := 1; id <= 8; id++ {
		if err := nodes[id].Listen(listenerReady); err != nil {
			fmt.Fprintf(os.Stderr, "listen node%d: %v\n", id, err)
			os.Exit(1)
		}
	}
	for range 8 {
		<-listenerReady
	}

	// Establish duplex connections sequentially: for each edge, the client dials
	// the server and then the server dials the client.
	for _, e := range edges {
		server, client := e[0], e[1]
		if err := nodes[client].Dial(server); err != nil {
			fmt.Fprintf(os.Stderr, "dial node%d->node%d: %v\n", client, server, err)
			os.Exit(1)
		}
		if err := nodes[server].Dial(client); err != nil {
			fmt.Fprintf(os.Stderr, "dial node%d->node%d: %v\n", server, client, err)
			os.Exit(1)
		}
	}
	fmt.Println("network ready — logs in log/node<N>.log, log/nodeCA.log")

	active := 1
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("node%d > ", active)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "":
		case strings.HasPrefix(line, "node "):
			var target int
			if _, err := fmt.Sscanf(line, "node %d", &target); err != nil || nodes[target] == nil {
				fmt.Println("unknown node")
			} else {
				active = target
			}
		case strings.HasPrefix(line, "broadcast "):
			fpath := strings.TrimPrefix(line, "broadcast ")
			data, err := os.ReadFile(fpath)
			if err != nil {
				fmt.Println("read file:", err)
			} else {
				nodes[active].Broadcast(string(data))
			}
		default:
			fmt.Println(`commands: node <N> | broadcast <filepath>`)
		}
		fmt.Printf("node%d > ", active)
	}
}
