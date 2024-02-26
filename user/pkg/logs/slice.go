package logs

import (
	"errors"
	"io"
	"net"
	"os"

	"github.com/rodaine/table"
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
	logsFile, err := os.Open(ReadLogsDeviceFile)
	if err != nil {
		return nil, err
	}
	defer logsFile.Close()

	buffer := make([]byte, 44*logBytesSize) // 44 * logByteSize is just under 1024 bytes
	logs := logsSlice{}
	for {
		bytesRead, err := logsFile.Read(buffer)
		if errors.Is(err, io.EOF) {
			return logs, nil
		} else if err != nil {
			return nil, err
		}
		for i := 0; i < bytesRead; i += logBytesSize {
			logs = append(logs, *Unmarshal(buffer[i : i+logBytesSize]))
		}
	}
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

func (logs *logsSlice) Table() table.Table {
	tbl := table.New("Timestamp", "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol", "Action", "Reason", "Count")
	for _, log := range *logs {
		tbl.AddRow(
			log.Timestamp.Format(logsDateTimeFormat),
			net.IP(log.SrcIp[:]),
			net.IP(log.DstIp[:]),
			log.SrcPort,
			log.DstPort,
			log.Protocol,
			log.Action,
			log.Reason,
			log.Count,
		)
	}
	return tbl
}
