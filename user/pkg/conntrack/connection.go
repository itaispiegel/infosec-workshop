package conntrack

import (
	"bytes"
	"encoding/binary"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwtypes"
	"github.com/itaispiegel/infosec-workshop/user/pkg/utils"
)

type Connection struct {
	SrcIp    [4]byte
	SrcPort  uint16
	DestIp   [4]byte
	DestPort uint16
	State    fwtypes.TcpState
}

func Unmarshal(data []byte) *Connection {
	var conn Connection
	reader := bytes.NewReader(data)
	utils.PanicIfError(binary.Read(reader, binary.BigEndian, &conn.SrcIp))
	utils.PanicIfError(binary.Read(reader, binary.BigEndian, &conn.SrcPort))
	utils.PanicIfError(binary.Read(reader, binary.BigEndian, &conn.DestIp))
	utils.PanicIfError(binary.Read(reader, binary.BigEndian, &conn.DestPort))
	utils.PanicIfError(binary.Read(reader, binary.LittleEndian, &conn.State))
	return &conn
}

func (c *Connection) Marshal() []byte {
	return nil
}

func (c *Connection) String() string {
	return ""
}
