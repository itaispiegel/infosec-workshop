package rulestable

import (
	"os"

	"github.com/itaispiegel/infosec-workshop/user/pkg/rules"
)

const (
	RuleTableDeviceFile = "/sys/class/fw/rules/rules"
	ruleBytesSize       = 64
)

// Adds a rule to the firewall rule table.
func AddRule(rule rules.Rule) error {
	buf := rule.Marshal()

	f, err := os.OpenFile(RuleTableDeviceFile, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(buf)
	if err != nil {
		return err
	}

	return nil
}

// Reads the rule table from the firewall rule table device file, and returns it.
func ReadRules() ([]rules.Rule, error) {
	buf, err := os.ReadFile(RuleTableDeviceFile)
	if err != nil {
		return nil, err
	}

	table := []rules.Rule{}
	for i := 0; i < len(buf); i += ruleBytesSize {
		table = append(table, rules.Unmarshal(buf[i:i+ruleBytesSize]))
	}

	return table, nil
}
