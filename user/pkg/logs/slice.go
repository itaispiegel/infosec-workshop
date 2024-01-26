package logs

import (
	"os"
	"strings"
)

type logsSlice []Log

const (
	LogsDeviceFile = "/dev/fw_log"
	logBytesSize   = 23
)

func ReadFromDevice() (logsSlice, error) {
	buf, err := os.ReadFile(LogsDeviceFile)
	if err != nil {
		return nil, err
	}

	logs := []Log{}
	for i := 0; i < len(buf); i += logBytesSize {
		logs = append(logs, *Unmarshal(buf[i : i+logBytesSize]))
	}

	return logs, nil
}

func (logs *logsSlice) String() string {
	sb := strings.Builder{}
	// TODO is it okay that the headers are capitalized?
	sb.WriteString(
		"Timestamp           " +
			"SrcIP    " +
			"DstIP   " +
			"SrcPort DstPort  Protocol Action Reason Count",
	)

	for _, log := range *logs {
		sb.WriteString("\n" + log.ToString())
	}
	return sb.String()
}
