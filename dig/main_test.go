package main

import "testing"

func TestWalkName(t *testing.T) {
	// ;; ANSWER SECTION:
	// www.facebook.com.			2256	IN	CNAME	star-mini.c10r.facebook.com.
	// star-mini.c10r.facebook.com. 25		IN	A	31.13.77.36
	b := []byte{
		0xe0, 0xba, 0x81, 0x80, 0x0, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		// pointers
		// 12 0x0c: www.facebook.com
		0x03, 0x77, 0x77, 0x77,
		// 16 0x10: faceboo.com
		0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b,
		// 25 0x19: com
		0x03, 0x63, 0x6f, 0x6d,
		// termination
		0x00,

		0x00, 0x01,
		0x00, 0x01,

		// 34
		0xc0, 0x0c, // offset to 12 = 0x0c
		0x00, 0x05, // Type CNAME
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x08, 0xd0, // TTL 2256
		0x00, 0x11, // RDLength 17

		// 46
		0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69, // star-mini
		0x04, 0x63, 0x31, 0x30, 0x72, // c10r
		0xc0, 0x10, // offset to 16 = 0x10 "facebook.com"

		// 63
		0xc0, 0x2e, // offset
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0xc, // TTL
		0x00, 0x04, // RDLength
		0x1f, 0xd, 0x4d, 0x24, 0x00, // RData
	}

	for _, tt := range []struct {
		off int
		out string
	}{
		{12, "www.facebook.com."},
		{16, "facebook.com."},
		{25, "com."},
	} {
		if labels(b, tt.off) != tt.out {
			t.Errorf("labels(b, %v) did not match %v", tt.off, tt.out)
		}
	}

	for _, tt := range []struct {
		off0 int
		out  string
		off  int
		next byte
	}{
		{12, "www.facebook.com.", 30, 0x00},
		{46, "star-mini.c10r.facebook.com.", 63, 0xc0},
	} {
		out, off := decompName(b, tt.off0)
		if out != tt.out {
			t.Errorf("walkName(b, %v) expected output %v but got %v)", tt.off0, tt.out, out)
		}
		if off != tt.off {
			t.Errorf("walkName(b, %v) expected offset %v but got %v)", tt.off0, tt.off, off)
		}
		if b[off] != tt.next {
			t.Errorf("walkName(b, %v) expected next byte was %v but got %v)", tt.off0, tt.next, b[off])
		}
	}
}
