package fwtypes

const (
	TcpEstablished = 1
	TcpSynSent     = 2
	TcpSynRecv     = 3
	TcpFinWait1    = 4
	TcpFinWait2    = 5
	TcpTimeWait    = 6
	TcpClose       = 7
	TcpCloseWait   = 8
	TcpLastAck     = 9
	TcpListen      = 10
	TcpClosing     = 11
	TcpNewSynRecv  = 12
)

type TcpState uint8

func (t TcpState) String() string {
	switch t {
	case TcpEstablished:
		return "ESTABLISHED"
	case TcpSynSent:
		return "SYN_SENT"
	case TcpSynRecv:
		return "SYN_RECV"
	case TcpFinWait1:
		return "FIN_WAIT1"
	case TcpFinWait2:
		return "FIN_WAIT2"
	case TcpTimeWait:
		return "TIME_WAIT"
	case TcpClose:
		return "CLOSE"
	case TcpCloseWait:
		return "CLOSE_WAIT"
	case TcpLastAck:
		return "LAST_ACK"
	case TcpListen:
		return "LISTEN"
	case TcpClosing:
		return "CLOSING"
	case TcpNewSynRecv:
		return "NEW_SYN_RECV"
	default:
		return "UNKNOWN"
	}
}
