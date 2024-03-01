package conntrack

import (
	"bytes"
	"encoding/binary"
	"os"

	"github.com/itaispiegel/infosec-workshop/user/pkg/utils"
)

const (
	relatedConnsFile = "/sys/class/fw/conn/related_conns"
)

func AllowRelatedConnection(conn *Connection) error {
	var buf = bytes.NewBuffer(nil)
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, &conn.SrcIp))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, &conn.SrcPort))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, &conn.DestIp))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, &conn.DestPort))
	return os.WriteFile(relatedConnsFile, buf.Bytes(), 0644)
}
