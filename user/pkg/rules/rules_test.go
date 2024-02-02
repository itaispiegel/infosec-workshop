package rules

import (
	"net"
	"strings"
	"testing"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwtypes"
	"github.com/stretchr/testify/assert"
)

func TestNewRuleWithTooLongName(t *testing.T) {
	rule := NewRule(
		strings.Repeat("a", RuleNameSizeLimit+1),
		fwtypes.DirectionIn,
		net.IPv4(1, 2, 3, 4),
		net.CIDRMask(24, 32),
		net.IPv4(5, 6, 7, 8),
		net.CIDRMask(24, 32),
		0,
		0,
		fwtypes.ProtAny,
		fwtypes.AckAny,
		fwtypes.ActionAccept,
	)

	assert.Nil(t, rule)
}

func TestNewRule(t *testing.T) {
	rule := NewRule(
		"test",
		fwtypes.DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		fwtypes.ProtAny,
		fwtypes.AckAny,
		fwtypes.ActionAccept,
	)

	assert.Equal(t, [20]byte{'t', 'e', 's', 't'}, rule.Name)
}

func TestRuleUnmarshal(t *testing.T) {
	data := []byte{
		116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		fwtypes.DirectionAny,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		0, 0,
		0, 0,
		fwtypes.ProtAny,
		fwtypes.AckAny,
		fwtypes.ActionAccept,
	}
	unmarshaled := Unmarshal(data)
	expected := NewRule(
		"test",
		fwtypes.DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		fwtypes.ProtAny,
		fwtypes.AckAny,
		fwtypes.ActionAccept,
	)

	assert.Equal(t, expected, unmarshaled)
}

func TestRuleMarshal(t *testing.T) {
	rule := NewRule(
		"test",
		fwtypes.DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		fwtypes.ProtAny,
		fwtypes.AckAny,
		fwtypes.ActionAccept,
	)
	expected := []byte{
		116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		fwtypes.DirectionAny,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		0, 0,
		0, 0,
		fwtypes.ProtAny,
		fwtypes.AckAny,
		fwtypes.ActionAccept,
	}

	assert.Equal(t, expected, rule.Marshal())
}
