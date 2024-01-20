package module

import (
	"os"
	"strings"
)

const (
	loadedModulesFile = "/proc/modules"
	moduleName        = "firewall"
)

// Returns whether the firewall kernel module is loaded.
// If there was an error reading the modules file, returns false.
func IsLoaded() bool {
	modules, err := os.ReadFile(loadedModulesFile)
	if err != nil {
		return false
	}

	lines := strings.Split(string(modules), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, moduleName+" ") {
			return true
		}
	}

	return false
}
