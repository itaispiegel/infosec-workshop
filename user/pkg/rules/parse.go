package rules

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwtypes"
)

var ErrInvalidRuleFormat = errors.New("invalid rule format")

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

// Parses a rule line into a Rule struct.
func ParseRule(ruleLine string) (*Rule, error) {
	fields := strings.Split(ruleLine, " ")
	if len(fields) != 9 {
		return &Rule{}, ErrInvalidRuleFormat
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

	direction, err := fwtypes.DirectionFromString(rawDirection)
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

	protocol, err := fwtypes.ProtocolFromString(rawProtocol)
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

	ack, err := fwtypes.AckFromString(rawAck)
	if err != nil {
		return nil, err
	}

	action, err := fwtypes.ActionFromString(rawAction)
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
