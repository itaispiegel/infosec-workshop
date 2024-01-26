package logs

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwtypes"
)

const (
	logsDateTimeFormat = "02/01/2006 15:04:05"
)

type Log struct {
	Timestamp uint32
	fwtypes.Protocol
	fwtypes.Action
	SrcIp   [4]byte
	DstIp   [4]byte
	SrcPort uint16
	DstPort uint16
	Reason  int8
	Count   uint32
}

func NewLog(
	timestamp time.Time,
	protocol fwtypes.Protocol,
	srcIp,
	dstIp net.IP,
	srcPort,
	dstPort uint16,
	reason int8,
	count uint32) *Log {

	return &Log{
		Timestamp: uint32(timestamp.Unix()),
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
	var log Log
	reader := bytes.NewReader(data)
	binary.Read(reader, binary.LittleEndian, &log.Timestamp)
	binary.Read(reader, binary.LittleEndian, &log.Protocol)
	binary.Read(reader, binary.LittleEndian, &log.Action)
	binary.Read(reader, binary.BigEndian, &log.SrcIp)
	binary.Read(reader, binary.BigEndian, &log.DstIp)
	binary.Read(reader, binary.BigEndian, &log.SrcPort)
	binary.Read(reader, binary.BigEndian, &log.DstPort)
	binary.Read(reader, binary.LittleEndian, &log.Reason)
	binary.Read(reader, binary.LittleEndian, &log.Count)
	return &log
}

func (log *Log) Marshal() []byte {
	panic("Not implemented")
}

func (log *Log) ToString() string {
	// TODO find a better solution for formatting the table's spaces
	ts := time.Unix(int64(log.Timestamp), 0)
	sb := strings.Builder{}
	sb.WriteString(ts.Format(logsDateTimeFormat))
	sb.WriteByte(' ')

	sb.WriteString(net.IP(log.SrcIp[:]).String() + " ")
	sb.WriteString(net.IP(log.DstIp[:]).String() + " ")

	sb.WriteString(strconv.Itoa(int(log.SrcPort)) + "    ")
	sb.WriteString(strconv.Itoa(int(log.DstPort)) + "       ")

	sb.WriteString(log.Protocol.String() + "      ")
	sb.WriteString(log.Action.String() + " ")

	// TODO handle different reasons
	sb.WriteString(strconv.Itoa(int(log.Reason)) + "      ")
	sb.WriteString(strconv.Itoa(int(log.Count)))

	return sb.String()
}