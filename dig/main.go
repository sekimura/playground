package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
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

	query, err := pack(name)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := conn.Write(query.Bytes()); err != nil {
		log.Fatal(err)
	}

	answer := make([]byte, 512)
	_, err = bufio.NewReader(conn).Read(answer)
	if err != nil {
		log.Fatal(err)
	}

	out := new(bytes.Buffer)

	fmt.Fprintf(out, "%s has address ", name)
	// Skip Question Section and pick the last four octets
	offset := len(query.Bytes()) + 12
	for i := offset; i < offset+4; i++ {
		if i > offset {
			fmt.Fprint(out, ".")
		}
		fmt.Fprint(out, answer[i])
	}

	fmt.Println(out.String())
}

type msgHeader struct {
	id      uint16
	bits    [2]byte
	qdcount uint16
	ancount uint16
	nscount uint16
	arcount uint16
}

type msgQuestionFooter struct {
	qtype  uint16
	qclass uint16
}

func pack(name string) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)

	h := msgHeader{
		id:      uint16(rand.Intn(1 << 16)),
		bits:    [2]byte{1, 0},
		qdcount: uint16(1),
		ancount: uint16(0),
		nscount: uint16(0),
		arcount: uint16(0),
	}
	if err := binary.Write(b, binary.BigEndian, &h); err != nil {
		return nil, err
	}

	// QNAME
	for _, label := range strings.Split(name, ".") {
		// byte is just an alias for uint8
		l := uint8(len(label))
		b.WriteByte(uint8(l))
		if l > 0 {
			b.WriteString(label)
		}
	}

	f := msgQuestionFooter{
		qtype:  uint16(1), // A
		qclass: uint16(1), // IN
	}
	if err := binary.Write(b, binary.BigEndian, &f); err != nil {
		return nil, err
	}

	return b, nil
}
