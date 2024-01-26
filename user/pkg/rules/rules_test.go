package rules

import (
	"net"
	"strings"
	"testing"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwconsts"
	"github.com/stretchr/testify/assert"
)

func TestNewRuleWithTooLongName(t *testing.T) {
	rule := NewRule(
		strings.Repeat("a", RuleNameSizeLimit+1),
		DirectionIn,
		net.IPv4(1, 2, 3, 4),
		net.CIDRMask(24, 32),
		net.IPv4(5, 6, 7, 8),
		net.CIDRMask(24, 32),
		0,
		0,
		fwconsts.ProtAny,
		AckAny,
		ActionAccept,
	)

	assert.Nil(t, rule)
}

func TestNewRule(t *testing.T) {
	rule := NewRule(
		"test",
		DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		fwconsts.ProtAny,
		AckAny,
		ActionAccept,
	)

	assert.Equal(t, [20]byte{'t', 'e', 's', 't'}, rule.Name)
}

func TestRuleUnmarshal(t *testing.T) {
	data := []byte{
		116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		DirectionAny,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		0, 0,
		0, 0,
		fwconsts.ProtAny,
		AckAny,
		ActionAccept,
	}
	unmarshaled := Unmarshal(data)
	expected := NewRule(
		"test",
		DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		fwconsts.ProtAny,
		AckAny,
		ActionAccept,
	)

	assert.Equal(t, expected, unmarshaled)
}

func TestRuleMarshal(t *testing.T) {
	rule := NewRule(
		"test",
		DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		fwconsts.ProtAny,
		AckAny,
		ActionAccept,
	)
	expected := []byte{
		116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		DirectionAny,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		127, 0, 0, 1,
		255, 0, 0, 0,
		8,
		0, 0,
		0, 0,
		fwconsts.ProtAny,
		AckAny,
		ActionAccept,
	}

	assert.Equal(t, expected, rule.Marshal())
}
