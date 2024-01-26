package rules

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwconsts"
)

func parseDirection(direction string) (uint8, error) {
	switch direction {
	case "in":
		return DirectionIn, nil
	case "out":
		return DirectionOut, nil
	case "any":
		return DirectionAny, nil
	default:
		return 0, errors.New("invalid direction")
	}
}

func parseCidr(cidr string) (net.IP, net.IPMask, error) {
	if cidr == "any" {
		return net.IPv4(0, 0, 0, 0), net.CIDRMask(0, 32), nil
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	return ip, ipNet.Mask, nil
}

func parsePort(port string) (uint16, error) {
	switch port {
	case "any":
		return 0, nil
	case ">1023":
		return 1023, nil
	default:
		parsedPort, err := strconv.Atoi(port)
		return uint16(parsedPort), err
	}
}

func parseProtocol(protocol string) (uint8, error) {
	switch protocol {
	case "icmp":
		return fwconsts.ProtIcmp, nil
	case "tcp":
		return fwconsts.ProtTcp, nil
	case "udp":
		return fwconsts.ProtUdp, nil
	case "other":
		return fwconsts.ProtOther, nil
	case "any":
		return fwconsts.ProtAny, nil
	default:
		return 0, errors.New("invalid protocol")
	}
}

func parseAck(ack string) (uint8, error) {
	switch ack {
	case "no":
		return AckNo, nil
	case "yes":
		return AckYes, nil
	case "any":
		return AckAny, nil
	default:
		return 0, errors.New("invalid ack")
	}
}

func parseAction(action string) (uint8, error) {
	switch action {
	case "drop":
		return ActionDrop, nil
	case "accept":
		return ActionAccept, nil
	default:
		return 0, errors.New("invalid action")
	}
}

// Parses a rule line into a Rule struct.
func ParseRule(ruleLine string) (*Rule, error) {
	fields := strings.Split(ruleLine, " ")
	if len(fields) != 9 {
		return &Rule{}, errors.New("invalid rule format")
	}

	name := fields[0]
	rawDirection := strings.ToLower(fields[1])
	srcCidr := fields[2]
	dstCidr := fields[3]
	rawProtocol := strings.ToLower(fields[4])
	rawSrcPort := fields[5]
	rawDstPort := fields[6]
	rawAck := strings.ToLower(fields[7])
	rawAction := strings.ToLower(fields[8])

	direction, err := parseDirection(rawDirection)
	if err != nil {
		return nil, err
	}

	srcIp, srcIpNetMask, err := parseCidr(srcCidr)
	if err != nil {
		return nil, err
	}

	dstIp, dstIpNetMask, err := parseCidr(dstCidr)
	if err != nil {
		return nil, err
	}

	protocol, err := parseProtocol(rawProtocol)
	if err != nil {
		return nil, err
	}

	srcPort, err := parsePort(rawSrcPort)
	if err != nil {
		return nil, err
	}

	dstPort, err := parsePort(rawDstPort)
	if err != nil {
		return nil, err
	}

	ack, err := parseAck(rawAck)
	if err != nil {
		return nil, err
	}

	action, err := parseAction(rawAction)
	if err != nil {
		return nil, err
	}

	return NewRule(
		name,
		direction,
		srcIp,
		srcIpNetMask,
		dstIp,
		dstIpNetMask,
		srcPort,
		dstPort,
		protocol,
		ack,
		action,
	), nil
}
