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

	query, err := pack(name, *flagType)
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

	msg, err := unpack(answer)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < int(msg.Header.ANcount); i++ {
		rr := msg.RRs[i]
		switch rr.Type {
		case 0x5:
			fmt.Printf("%s is an alias for %s\n", rr.Name, rr.RData)
		case 0x1, 0x01c:
			fmt.Printf("%s has an address %s\n", rr.Name, rr.RData)
		}
	}
}

func pack(name, qtypeStr string) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)

	h := MsgHeader{
		ID:      uint16(rand.Intn(1 << 16)),
		Bits:    [2]byte{1, 0},
		QDcount: uint16(1),
		ANcount: uint16(0),
		NScount: uint16(0),
		ARcount: uint16(0),
	}
	if err := binary.Write(b, binary.BigEndian, &h); err != nil {
		return nil, err
	}

	// QNAME
	for _, label := range strings.Split(name, ".") {
		// byte is just an alias for uint8
		l := uint8(len(label))
		b.WriteByte(l)
		if l > 0 {
			b.WriteString(label)
		}
	}

	var qtype MsgQtype
	switch qtypeStr {
	case "A":
		qtype = MsgQtype(1)
	case "AAAA":
		qtype = MsgQtype(28)
	}

	f := struct {
		Qtype  MsgQtype
		Qclass MsgQclass
	}{
		Qtype:  qtype,
		Qclass: MsgQclass(1), // IN
	}
	if err := binary.Write(b, binary.BigEndian, &f); err != nil {
		return nil, err
	}

	return b, nil
}

type Msg struct {
	Header MsgHeader
	QName  string
	Qtype  MsgQtype
	Qclass MsgQclass
	RRs    []RR
}

type MsgHeader struct {
	ID      uint16
	Bits    [2]byte
	QDcount uint16
	ANcount uint16
	NScount uint16
	ARcount uint16
}

type MsgQtype uint16
type MsgQclass uint16

type RR struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    interface{}
}

func unpack(b []byte) (*Msg, error) {
	var h MsgHeader
	buf := bytes.NewBuffer(b[:12])
	if err := binary.Read(buf, binary.BigEndian, &h); err != nil {
		return nil, err
	}
	qname, n := decompName(b, 12)
	off := 12 + n

	var f struct {
		Qtype  MsgQtype
		Qclass MsgQclass
	}
	buf = bytes.NewBuffer(b[off : off+4])
	if err := binary.Read(buf, binary.BigEndian, &f); err != nil {
		return nil, err
	}
	off += 4

	ret := Msg{
		Header: h,
		QName:  qname,
		Qtype:  f.Qtype,
		Qclass: f.Qclass,

		RRs: make([]RR, int(h.ANcount)),
	}

	for i := 0; i < int(h.ANcount); i++ {
		name, n := decompName(b, off)
		off += n
		var m struct {
			Type     uint16
			Class    uint16
			TTL      uint32
			RDLength uint16
		}
		buf = bytes.NewBuffer(b[off : off+10])
		if err := binary.Read(buf, binary.BigEndian, &m); err != nil {
			return nil, err
		}
		off += 10

		rr := RR{
			Name:     name,
			Type:     m.Type,
			Class:    m.Class,
			TTL:      m.TTL,
			RDLength: m.RDLength,
		}
		switch rr.Type {
		case 0x5: // CNAME
			aname, n := decompName(b, off)
			rr.RData = aname
			off += n
		case 0x1: // A
			rr.RData = net.IP(b[off : off+net.IPv4len])
			off += 4
		case 0x1c: // AAAA
			rr.RData = net.IP(b[off : off+net.IPv6len])
			off += 4
		}

		ret.RRs[i] = rr
	}

	return &ret, nil
}

// decompName decompress RFC 1035 4.1.4. Message compression and returns name
// as string and read bytes count as int
func decompName(b []byte, off int) (string, int) {
	buf := bytes.NewBuffer(nil)
	off0 := off
	for {
		c := b[off]
		if c >= 0xc0 {
			// TODO: handle 01 and 10 bits cases
			// technically offset is uint14 value
			off += 1
			p := binary.BigEndian.Uint16([]byte{c ^ 0xc0, b[off]})
			s, _ := decompName(b, int(p))
			buf.WriteString(s)
			break
		} else {
			if c == 0 {
				break
			}
			l := int(b[off])
			off += 1
			buf.Write(b[off : off+l])
			buf.WriteString(".")
			off += l
		}
	}
	return buf.String(), off - off0 + 1
}
