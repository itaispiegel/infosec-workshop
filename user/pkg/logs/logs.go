package logs

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwtypes"
)

const (
	logsDateTimeFormat = "02/01/2006 15:04:05"
)

type Log struct {
	Timestamp time.Time
	fwtypes.Protocol
	fwtypes.Action
	SrcIp   [4]byte
	DstIp   [4]byte
	SrcPort uint16
	DstPort uint16
	fwtypes.Reason
	Count uint32
}

func NewLog(
	timestamp time.Time,
	protocol fwtypes.Protocol,
	srcIp,
	dstIp net.IP,
	srcPort,
	dstPort uint16,
	reason fwtypes.Reason,
	count uint32) *Log {

	return &Log{
		Timestamp: timestamp,
		Protocol:  protocol,
		SrcIp:     [4]byte(srcIp.To4()),
		DstIp:     [4]byte(dstIp.To4()),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Reason:    reason,
		Count:     count,
	}
}

func Unmarshal(data []byte) *Log {
	var (
		timestamp uint32
		log       Log
	)
	reader := bytes.NewReader(data)
	binary.Read(reader, binary.LittleEndian, &timestamp)
	binary.Read(reader, binary.LittleEndian, &log.Protocol)
	binary.Read(reader, binary.LittleEndian, &log.Action)
	binary.Read(reader, binary.BigEndian, &log.SrcIp)
	binary.Read(reader, binary.BigEndian, &log.DstIp)
	binary.Read(reader, binary.BigEndian, &log.SrcPort)
	binary.Read(reader, binary.BigEndian, &log.DstPort)
	binary.Read(reader, binary.LittleEndian, &log.Reason)
	binary.Read(reader, binary.LittleEndian, &log.Count)
	log.Timestamp = time.Unix(int64(timestamp), 0)
	return &log
}

func (log *Log) Marshal() []byte {
	panic("Not implemented")
}
