package fwtypes

import "errors"

const (
	AckNo  = 0x01
	AckYes = 0x02
	AckAny = AckNo | AckYes
)

type Ack uint8

func AckFromString(ack string) (Ack, error) {
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

func (a Ack) String() string {
	switch a {
	case AckNo:
		return "no"
	case AckYes:
		return "yes"
	case AckAny:
		return "any"
	default:
		return "unknown"
	}
}
