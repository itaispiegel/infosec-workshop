package fwtypes

import "errors"

const (
	DirectionIn  = 0x01
	DirectionOut = 0x02
	DirectionAny = DirectionIn | DirectionOut
)

type Direction uint8

func DirectionFromString(direction string) (Direction, error) {
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

func (d Direction) String() string {
	switch d {
	case DirectionIn:
		return "in"
	case DirectionOut:
		return "out"
	case DirectionAny:
		return "any"
	default:
		return "unknown"
	}
}
