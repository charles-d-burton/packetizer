package packetizer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

type TcpHeader struct {
	Src      uint16
	Dst      uint16
	Seq      uint32
	Ack      uint32
	Flags    uint16
	Window   uint16
	ChkSum   uint16
	UPointer uint16
}

type TcpOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

func GenerateSyn(laddr string, raddr string, sport uint16, dport uint16) ([]byte, error) {
	options := []TcpOption{
		{
			Kind:   2,
			Length: 4,
			Data:   []byte{0x05, 0xb4},
		},
		{
			Kind: 0,
		},
	}
	header := TcpHeader{
		Src:      sport,
		Dst:      dport,
		Seq:      rand.Uint32(),
		Ack:      0,
		Flags:    0x8002, //the SYN flag
		Window:   1024,
		ChkSum:   0,
		UPointer: 0,
	}
	return GeneratePacket(header, options, laddr, raddr)
}

func GeneratePacket(header TcpHeader, options []TcpOption, laddr string, raddr string) ([]byte, error) {
	if !isValidIP(laddr) || !isValidIP(raddr) {
		return nil, fmt.Errorf("ip addresse(s) %s or %s are invalid", laddr, raddr)
	}

	//build dummy packet for checksum
	buff := bytes.NewBuffer([]byte{})

	binary.Write(buff, binary.BigEndian, header)
	for i := range options {
		binary.Write(buff, binary.BigEndian, options[i].Kind)
		binary.Write(buff, binary.BigEndian, options[i].Length)
		binary.Write(buff, binary.BigEndian, options[i].Data)
	}

	binary.Write(buff, binary.BigEndian, [6]byte{})
	data := buff.Bytes()
	checksum := checkSum(data, ipstr2Bytes(laddr), ipstr2Bytes(raddr))
	header.ChkSum = checksum

	//build the final packet
	buff.Reset()
	binary.Write(buff, binary.BigEndian, header)
	for i := range options {
		binary.Write(buff, binary.BigEndian, options[i].Kind)
		binary.Write(buff, binary.BigEndian, options[i].Length)
		binary.Write(buff, binary.BigEndian, options[i].Data)
	}
	binary.Write(buff, binary.BigEndian, [6]byte{})

	return buff.Bytes(), nil
}

/* Generate a pseudoheader
 * This is added during the checksum calculation.  This is not sent as part of the TCP segment,
 * rather is assures the receiver that a routing or fragmentation process did no modify the
 * important fields of the IP header
 * https://www.oreilly.com/library/view/windows-server-2008/9780735624474/ch10s06.html#:~:text=The%20TCP%20pseudo%20header%20is%20added%20to%20the%20beginning%20of,fields%20in%20the%20IP%20header.
 */

func checkSum(data []byte, src, dst [4]byte) uint16 {
	// 4 bytes from srce
	// 4 bytes from dst
	// unused
	// 6 (static)
	// unused
	// length of data
	pseudoHeader := []byte{
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0,
		6,
		0,
		byte(len(data)),
	}

	totalLength := len(pseudoHeader) + len(data)
	if totalLength%2 != 0 {
		totalLength++
	}

	d := make([]byte, 0, totalLength)
	d = append(d, pseudoHeader...)
	d = append(d, data...)

	var sum uint32
	for i := 0; i < len(d)-1; i += 2 {
		sum += uint32(uint16(d[i])<<8 | uint16(d[i+1]))
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// XOR the result
	return ^uint16(sum)
}

// Convert an IPv4 address into a byte array
func ipstr2Bytes(addr string) [4]byte {
	s := strings.Split(addr, ".")
	b0, _ := strconv.Atoi(s[0])
	b1, _ := strconv.Atoi(s[1])
	b2, _ := strconv.Atoi(s[2])
	b3, _ := strconv.Atoi(s[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}

func isValidIP(ip string) bool {
	if r := net.ParseIP(ip); r == nil {
		return false
	}
	return true
}
