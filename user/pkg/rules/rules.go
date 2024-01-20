package rules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	RuleNameSizeLimit = 20

	DirectionIn  = 0x01
	DirectionOut = 0x02
	DirectionAny = DirectionIn | DirectionOut

	AckNo  = 0x01
	AckYes = 0x02
	AckAny = AckNo | AckYes

	ProtIcmp  = 1
	ProtTcp   = 6
	ProtUdp   = 17
	ProtOther = 255
	ProtAny   = 143

	ActionDrop   = 0
	ActionAccept = 1
)

type Rule struct {
	Name          [RuleNameSizeLimit]byte
	Direction     uint8
	SrcIp         [4]byte
	SrcPrefixMask [4]byte
	SrcPrefixSize uint8
	DstIp         [4]byte
	DstPrefixMask [4]byte
	DstPrefixSize uint8
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	Ack           uint8
	Action        uint8
}

// Creates a new rule.
func NewRule(
	name string,
	direction uint8,
	srcIp [4]byte,
	srcPrefixMask [4]byte,
	srcPrefixSize uint8,
	dstIp [4]byte,
	dstPrefixMask [4]byte,
	dstPrefixSize uint8,
	srcPort uint16,
	dstPort uint16,
	protocol uint8,
	ack uint8,
	action uint8) (Rule, error) {
	if len(name) > RuleNameSizeLimit {
		return Rule{}, errors.New("name is too long")
	}

	nameSlice := [RuleNameSizeLimit]byte{0}
	copy(nameSlice[:], []byte(name))

	return Rule{
		Name:          nameSlice,
		Direction:     direction,
		SrcIp:         srcIp,
		SrcPrefixMask: srcPrefixMask,
		SrcPrefixSize: srcPrefixSize,
		DstIp:         dstIp,
		DstPrefixMask: dstPrefixMask,
		DstPrefixSize: dstPrefixSize,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Protocol:      protocol,
		Ack:           ack,
		Action:        action,
	}, nil
}

// Unmarshals a rule from a byte slice.
func Unmarshal(data []byte) Rule {
	var rule Rule
	reader := bytes.NewReader(data)
	binary.Read(reader, binary.LittleEndian, &rule.Name)
	binary.Read(reader, binary.LittleEndian, &rule.Direction)
	binary.Read(reader, binary.BigEndian, &rule.SrcIp)
	binary.Read(reader, binary.BigEndian, &rule.SrcPrefixMask)
	binary.Read(reader, binary.LittleEndian, &rule.SrcPrefixSize)
	binary.Read(reader, binary.BigEndian, &rule.DstIp)
	binary.Read(reader, binary.BigEndian, &rule.DstPrefixMask)
	binary.Read(reader, binary.LittleEndian, &rule.DstPrefixSize)
	binary.Read(reader, binary.LittleEndian, &rule.SrcPort)
	binary.Read(reader, binary.LittleEndian, &rule.DstPort)
	binary.Read(reader, binary.LittleEndian, &rule.Protocol)
	binary.Read(reader, binary.LittleEndian, &rule.Ack)
	binary.Read(reader, binary.LittleEndian, &rule.Action)
	return rule
}

// Marshals a rule to a byte slice.
func (rule *Rule) Marshal() []byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, rule.Name)
	binary.Write(buf, binary.LittleEndian, rule.Direction)
	binary.Write(buf, binary.BigEndian, rule.SrcIp)
	binary.Write(buf, binary.BigEndian, rule.SrcPrefixMask)
	binary.Write(buf, binary.LittleEndian, rule.SrcPrefixSize)
	binary.Write(buf, binary.BigEndian, rule.DstIp)
	binary.Write(buf, binary.BigEndian, rule.DstPrefixMask)
	binary.Write(buf, binary.LittleEndian, rule.DstPrefixSize)
	binary.Write(buf, binary.LittleEndian, rule.SrcPort)
	binary.Write(buf, binary.LittleEndian, rule.DstPort)
	binary.Write(buf, binary.LittleEndian, rule.Protocol)
	binary.Write(buf, binary.LittleEndian, rule.Ack)
	binary.Write(buf, binary.LittleEndian, rule.Action)
	return buf.Bytes()
}

// Returns a string representation of the rule.
func (rule *Rule) ToString() string {
	sb := strings.Builder{}
	sb.Write(rule.Name[:])
	sb.WriteByte(' ')
	switch rule.Direction {
	case DirectionIn:
		sb.WriteString("in")
	case DirectionOut:
		sb.WriteString("out")
	case DirectionAny:
		sb.WriteString("any")
	}
	sb.WriteByte(' ')

	sb.WriteString(net.IP(rule.SrcIp[:]).String() + "/" + strconv.Itoa(int(rule.SrcPrefixSize)) + " ")
	sb.WriteString(net.IP(rule.DstIp[:]).String() + "/" + strconv.Itoa(int(rule.DstPrefixSize)) + " ")

	if rule.SrcPort == 0 {
		sb.WriteString("any ")
	} else if rule.SrcPort == 1023 {
		sb.WriteString(">1023 ")
	} else {
		sb.WriteString(strconv.Itoa(int(rule.SrcPort)) + " ")
	}

	if rule.DstPort == 0 {
		sb.WriteString("any ")
	} else if rule.DstPort == 1023 {
		sb.WriteString(">1023 ")
	} else {
		sb.WriteString(strconv.Itoa(int(rule.DstPort)) + " ")
	}

	switch rule.Protocol {
	case ProtIcmp:
		sb.WriteString("icmp ")
	case ProtTcp:
		sb.WriteString("tcp ")
	case ProtUdp:
		sb.WriteString("udp ")
	case ProtOther:
		sb.WriteString("other ")
	case ProtAny:
		sb.WriteString("any ")
	}

	switch rule.Ack {
	case AckNo:
		sb.WriteString("no ")
	case AckYes:
		sb.WriteString("yes ")
	case AckAny:
		sb.WriteString("any ")
	}

	switch rule.Action {
	case ActionDrop:
		sb.WriteString("drop")
	case ActionAccept:
		sb.WriteString("accept")
	}

	return sb.String()
}
