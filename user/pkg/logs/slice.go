package logs

import (
	"os"
	"strings"
)

type logsSlice []Log

const (
	ReadLogsDeviceFile  = "/dev/fw_log"
	ClearLogsDeviceFile = "/sys/class/fw/log/reset"
	logBytesSize        = 23
)

var (
	clearLogsMagic = []byte{'r', 'e', 's', 'e', 't', 0}
)

func ReadFromDevice() (logsSlice, error) {
	buf, err := os.ReadFile(ReadLogsDeviceFile)
	if err != nil {
		return nil, err
	}

	logs := []Log{}
	for i := 0; i < len(buf); i += logBytesSize {
		logs = append(logs, *Unmarshal(buf[i : i+logBytesSize]))
	}

	return logs, nil
}

func ClearLogsDevice() error {
	var f *os.File
	var err error
	if f, err = os.OpenFile(ClearLogsDeviceFile, os.O_WRONLY, 0); err != nil {
		return err
	}

	_, err = f.Write(clearLogsMagic)
	return err
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
