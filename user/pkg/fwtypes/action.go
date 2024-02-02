package fwtypes

import "errors"

const (
	ActionDrop   = 0
	ActionAccept = 1
)

type Action uint8

func ActionFromString(action string) (Action, error) {
	switch action {
	case "drop":
		return ActionDrop, nil
	case "accept":
		return ActionAccept, nil
	default:
		return 0, errors.New("invalid action")
	}
}

func (a Action) String() string {
	switch a {
	case ActionDrop:
		return "drop"
	case ActionAccept:
		return "accept"
	default:
		return "unknown"
	}
}
