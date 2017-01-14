package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/sekimura/dns"
)

var (
	flagType = flag.String("type", "A", "QType")
)

func init() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()
}

func main() {

	name := flag.Arg(0)
	resolver := flag.Arg(1)

	if !strings.HasPrefix(name, ".") {
		name += "."
	}

	raddr, err := net.ResolveUDPAddr("udp", resolver+":53")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var qtype uint16
	switch *flagType {
	case "A":
		qtype = dns.QtypeA
	case "NS":
		qtype = dns.QtypeNS
	case "SOA":
		qtype = dns.QtypeSOA
	case "AAAA":
		qtype = dns.QtypeAAAA
	default:
		log.Fatal("unknown qtype", *flagType)
	}

	msg0 := &dns.Message{
		ID:       uint16(rand.Intn(1 << 16)),
		Flags:    uint16(0x0100),
		QDcount:  uint16(1),
		Question: make([]dns.Q, 1),
	}
	msg0.Question[0] = dns.Q{
		Name:  name,
		Type:  qtype,
		Class: dns.QclassIN,
	}

	b, err := dns.Pack(msg0)
	if err != nil {
		log.Fatal(err)
	}
	// log.Printf("%#v\n", b)

	if _, err := conn.Write(b); err != nil {
		log.Fatal(err)
	}

	bb := make([]byte, 512)
	_, err = bufio.NewReader(conn).Read(bb)
	if err != nil {
		log.Fatal(err)
	}

	// log.Printf("%#v\n", bb)

	msg, err := dns.Unpack(bb)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < int(msg.ANcount); i++ {
		rr := msg.Answer[i]
		switch rr.Type {
		case dns.QtypeCNAME:
			fmt.Printf("%s is an alias for %s\n", rr.Name, rr.RData)
		case dns.QtypeNS:
			fmt.Printf("%s has nameserver %s\n", rr.Name, rr.RData)
		case dns.QtypeA, dns.QtypeAAAA:
			fmt.Printf("%s has an address %s\n", rr.Name, rr.RData)
		default:
			fmt.Printf("%s has data %#v\n", rr.Name, rr.RData)
		}
	}

}
