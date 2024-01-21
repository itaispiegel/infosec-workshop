package rules

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRule(t *testing.T) {
	expected, err := NewRule(
		"test",
		DirectionAny,
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		net.IPv4(127, 0, 0, 1),
		net.CIDRMask(8, 32),
		0,
		0,
		ProtAny,
		AckAny,
		ActionAccept,
	)
	assert.NoError(t, err)

	actual, err := ParseRule("test any 127.0.0.1/8 127.0.0.1/8 any any any any accept")
	assert.NoError(t, err)

	assert.Equal(t, *expected, *actual)
}
