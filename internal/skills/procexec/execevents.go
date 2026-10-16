package procexec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"syscall"
	"time"
)

// The kernel's process events connector reports every exec as it happens.
// Polling /proc alone misses anything that runs and exits between polls, and
// a dropper that fetches a payload into /tmp, runs it and deletes it can be
// done in well under the 30s interval the skill ships with.

const (
	netlinkConnector  = 11 // NETLINK_CONNECTOR
	cnIdxProc         = 1  // CN_IDX_PROC
	cnValProc         = 1  // CN_VAL_PROC
	procCnMcastListen = 1  // PROC_CN_MCAST_LISTEN
	procEventExec     = 0x00000002

	nlmsgHdrLen = 16
	cnMsgLen    = 20
	// what (4), cpu (4), timestamp_ns (8), then the event's data
	procEventDataOff = nlmsgHdrLen + cnMsgLen + 16
)

// listenExecs sends the PID of each process that calls exec until ctx ends.
// It fails if the connector can't be subscribed to, e.g. without
// CAP_NET_ADMIN on older kernels.
func listenExecs(ctx context.Context) (<-chan int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return nil, fmt.Errorf("opening process events connector: %w", err)
	}
	fail := func(what string, err error) (<-chan int, error) {
		syscall.Close(fd)
		return nil, fmt.Errorf("%s: %w", what, err)
	}

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		return fail("binding process events connector", err)
	}
	// A build spawning thousands of processes shouldn't overrun the buffer;
	// the larger size needs root, so fall back quietly
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 4<<20) != nil {
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	}
	// Wake up regularly so the reader notices ctx ending
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fail("setting connector timeout", err)
	}
	if err := syscall.Sendto(fd, listenRequest(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fail("subscribing to process events", err)
	}

	pids := make(chan int, 256)
	go func() {
		defer close(pids)
		defer syscall.Close(fd)

		buf := make([]byte, 8192)
		lastOverrun := time.Time{}
		for ctx.Err() == nil {
			n, from, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				switch {
				case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
				case errors.Is(err, syscall.ENOBUFS):
					// Events were dropped; the next poll of /proc still sees
					// whatever is running
					if time.Since(lastOverrun) > time.Minute {
						log.Printf("[proc-exec] Process events overran the socket buffer; some execs were missed")
						lastOverrun = time.Now()
					}
				default:
					log.Printf("[proc-exec] Reading process events stopped: %v", err)
					return
				}
				continue
			}
			// Only the kernel's events count. Any process can send to this
			// socket's address, though a fake event only causes a lookup in /proc.
			if nl, ok := from.(*syscall.SockaddrNetlink); !ok || nl.Pid != 0 {
				continue
			}
			pid, ok := parseExecEvent(buf[:n])
			if !ok {
				continue
			}
			select {
			case pids <- pid:
			case <-ctx.Done():
				return
			}
		}
	}()
	return pids, nil
}

// listenRequest is the netlink message subscribing to process events
func listenRequest() []byte {
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	le := binary.LittleEndian
	le.PutUint32(msg[0:], uint32(len(msg))) // nlmsg_len
	le.PutUint16(msg[4:], syscall.NLMSG_DONE)
	le.PutUint32(msg[nlmsgHdrLen:], cnIdxProc)
	le.PutUint32(msg[nlmsgHdrLen+4:], cnValProc)
	le.PutUint16(msg[nlmsgHdrLen+16:], 4) // cn_msg len: the op below
	le.PutUint32(msg[nlmsgHdrLen+cnMsgLen:], procCnMcastListen)
	return msg
}

// parseExecEvent returns the process (thread group) ID from an exec event
func parseExecEvent(msg []byte) (int, bool) {
	le := binary.LittleEndian
	if len(msg) < procEventDataOff+8 {
		return 0, false
	}
	if le.Uint32(msg[nlmsgHdrLen:]) != cnIdxProc || le.Uint32(msg[nlmsgHdrLen+4:]) != cnValProc {
		return 0, false
	}
	if le.Uint32(msg[nlmsgHdrLen+cnMsgLen:]) != procEventExec {
		return 0, false
	}
	tgid := le.Uint32(msg[procEventDataOff+4:])
	if tgid == 0 {
		return 0, false
	}
	return int(tgid), true
}
