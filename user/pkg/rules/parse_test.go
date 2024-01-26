package rules

import (
	"net"
	"testing"

	"github.com/itaispiegel/infosec-workshop/user/pkg/fwconsts"
	"github.com/stretchr/testify/assert"
)

func TestParseRule(t *testing.T) {
	testCases := []struct {
		textual  string
		expected *Rule
	}{
		{
			textual: "myrule1 any 127.0.0.1/8 127.0.0.1/8 any any any any accept",
			expected: NewRule(
				"myrule1",
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
			),
		},
		{
			textual: "myrule2 in 1.1.1.1/21 any ICMP any >1023 yes drop",
			expected: NewRule(
				"myrule2",
				DirectionIn,
				net.IPv4(1, 1, 1, 1),
				net.CIDRMask(21, 32),
				net.IPv4(0, 0, 0, 0),
				net.CIDRMask(0, 32),
				0,
				1023,
				fwconsts.ProtIcmp,
				AckYes,
				ActionDrop,
			),
		},
	}

	for _, tc := range testCases {
		actual, err := ParseRule(tc.textual)
		assert.NoError(t, err)
		assert.Equal(t, *tc.expected, *actual)
	}
}
