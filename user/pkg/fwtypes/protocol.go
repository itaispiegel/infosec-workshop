package fwtypes

import "errors"

const (
	ProtIcmp  = 1
	ProtTcp   = 6
	ProtUdp   = 17
	ProtOther = 255
	ProtAny   = 143
)

type Protocol uint8

func ProtocolFromString(protocol string) (Protocol, error) {
	switch protocol {
	case "icmp":
		return ProtIcmp, nil
	case "tcp":
		return ProtTcp, nil
	case "udp":
		return ProtUdp, nil
	case "other":
		return ProtOther, nil
	case "any":
		return ProtAny, nil
	default:
		return 0, errors.New("invalid protocol")
	}
}

func (p Protocol) String() string {
	switch p {
	case ProtIcmp:
		return "icmp"
	case ProtTcp:
		return "tcp"
	case ProtUdp:
		return "udp"
	case ProtOther:
		return "other"
	case ProtAny:
		return "any"
	default:
		return "unknown"
	}
}
