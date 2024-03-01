package fwtypes

import "strconv"

const (
	ReasonFWInactive     = -1
	ReasonNoMatchingRule = -2
	ReasonXmasPacket     = -4
	ReasonIllegalValue   = -6
	ReasonRelated        = -8
)

type Reason int8

func (r Reason) String() string {
	switch {
	case r == ReasonNoMatchingRule:
		return "NoMatchingRule"
	case r == ReasonXmasPacket:
		return "XmasPacket"
	case r == ReasonRelated:
		return "Related"
	case r >= 0:
		return strconv.Itoa(int(r))
	default:
		return "Unknown"
	}
}
