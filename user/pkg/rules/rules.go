package rules

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwtypes"
)

const (
	RuleNameSizeLimit = 20
)

type Rule struct {
	Name [RuleNameSizeLimit]byte
	fwtypes.Direction
	SrcIp         [4]byte
	SrcPrefixMask [4]byte
	SrcPrefixSize uint8
	DstIp         [4]byte
	DstPrefixMask [4]byte
	DstPrefixSize uint8
	SrcPort       uint16
	DstPort       uint16
	fwtypes.Protocol
	fwtypes.Ack
	fwtypes.Action
}

// Creates a new rule.
func NewRule(
	name string,
	direction fwtypes.Direction,
	srcIp net.IP,
	srcPrefixMask net.IPMask,
	dstIp net.IP,
	dstPrefixMask net.IPMask,
	srcPort uint16,
	dstPort uint16,
	protocol fwtypes.Protocol,
	ack fwtypes.Ack,
	action fwtypes.Action) *Rule {

	if len(name) > RuleNameSizeLimit {
		return nil
	}

	nameSlice := [RuleNameSizeLimit]byte{0}
	copy(nameSlice[:], []byte(name))

	srcPrefixMaskSize, _ := srcPrefixMask.Size()
	dstPrefixMaskSize, _ := dstPrefixMask.Size()

	return &Rule{
		Name:          nameSlice,
		Direction:     direction,
		SrcIp:         [4]byte(srcIp.To4()),
		SrcPrefixMask: [4]byte(srcPrefixMask),
		SrcPrefixSize: uint8(srcPrefixMaskSize),
		DstIp:         [4]byte(dstIp.To4()),
		DstPrefixMask: [4]byte(dstPrefixMask),
		DstPrefixSize: uint8(dstPrefixMaskSize),
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Protocol:      protocol,
		Ack:           ack,
		Action:        action,
	}
}

// Unmarshals a rule from a byte slice.
func Unmarshal(data []byte) *Rule {
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
	binary.Read(reader, binary.BigEndian, &rule.SrcPort)
	binary.Read(reader, binary.BigEndian, &rule.DstPort)
	binary.Read(reader, binary.LittleEndian, &rule.Protocol)
	binary.Read(reader, binary.LittleEndian, &rule.Ack)
	binary.Read(reader, binary.LittleEndian, &rule.Action)
	return &rule
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
	binary.Write(buf, binary.BigEndian, rule.SrcPort)
	binary.Write(buf, binary.BigEndian, rule.DstPort)
	binary.Write(buf, binary.LittleEndian, rule.Protocol)
	binary.Write(buf, binary.LittleEndian, rule.Ack)
	binary.Write(buf, binary.LittleEndian, rule.Action)
	return buf.Bytes()
}

// Returns a string representation of the rule.
func (rule *Rule) String() string {
	sb := strings.Builder{}
	sb.Write(rule.Name[:])
	sb.WriteByte(' ')
	sb.WriteString(rule.Direction.String() + " ")

	sb.WriteString(net.IP(rule.SrcIp[:]).String() + "/" + strconv.Itoa(int(rule.SrcPrefixSize)) + " ")
	sb.WriteString(net.IP(rule.DstIp[:]).String() + "/" + strconv.Itoa(int(rule.DstPrefixSize)) + " ")

	sb.WriteString(rule.Protocol.String() + " ")

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

	sb.WriteString(rule.Ack.String() + " ")
	sb.WriteString(rule.Action.String())

	return sb.String()
}
