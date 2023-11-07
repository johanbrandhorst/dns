//go:build !windows
// +build !windows

package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// This is the required size of the OOB buffer to pass to ReadMsgUDP.
var udpOOBSize = func() int {
	// We can't know whether we'll get an IPv4 control message or an
	// IPv6 control message ahead of time. To get around this, we size
	// the buffer equal to the largest of the two.

	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)

	if len(oob4) > len(oob6) {
		return len(oob4)
	}

	return len(oob6)
}()

// SessionUDP holds the remote address and the associated
// out-of-band data.
type SessionUDP struct {
	raddr   *net.UDPAddr
	context []byte
}

// RemoteAddr returns the remote network address.
func (s *SessionUDP) RemoteAddr() net.Addr { return s.raddr }

// ReadFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
func ReadFromSessionUDP(conn *net.UDPConn, b []byte) (int, *SessionUDP, error) {
	oob := make([]byte, udpOOBSize)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, nil, err
	}
	// if err = fishForConnectionUid("ReadFromSessionUDP", conn, raddr); err != nil {
	// 	return n, nil, err
	// }
	return n, &SessionUDP{raddr, oob[:oobn]}, err
}

// WriteToSessionUDP acts just like net.UDPConn.WriteTo(), but uses a *SessionUDP instead of a net.Addr.
func WriteToSessionUDP(conn *net.UDPConn, b []byte, session *SessionUDP) (int, error) {
	oob := correctSource(session.context)
	n, _, err := conn.WriteMsgUDP(b, oob, session.raddr)
	if err != nil {
		return n, err
	}
	// if err = fishForConnectionUid("WriteToSessionUDP", conn, session.raddr); err != nil {
	// 	return n, err
	// }
	return n, err
}

// fishForConnectionUid will fish around with lsof and netstat to try and find
// out the UID for the remote connection.  If env DEBUG=1, it will output more
// info from lsof and netstat.
func fishForConnectionUid(caller string, conn *net.UDPConn, raddr *net.UDPAddr) error {

	debug := os.Getenv("DEBUG")

	op := fmt.Sprintf("%s->fishForConnectionUid", caller)

	localAddrPort := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	var infoBuf strings.Builder
	defer func() {
		log.Default().Print(fmt.Sprintf("\n\n%s for remote port:%d\n", op, raddr.Port), "info", infoBuf.String())
	}()
	// local == listen addr
	// remote == user's conn

	// lsof -i 4<protocol>:53 -l -P -n -Fnu
	//
	// `-i 4<protocol>:53` specifies the network connections to list (udp or tcp
	// protocol) the `4` designates ipv4 only
	// `-l` indicates we want a compact single line format
	// `-P` specifies to not resolve port names to service names
	// `-n` specifies to not resolve host names to IPs
	// `-F` specifies the output format will be custom and to prepend a single
	// character indicating the type of data
	// 		`n` tag indicates we want network info
	//		`u` tag indicates we want user info
	// Example output
	// u503
	// f3
	// n*:64163
	// f7
	// n[::1]:61963->[::1]:64163
	cmd := exec.CommandContext(context.Background(), "sudo", "/usr/sbin/lsof", "-i", fmt.Sprintf("%s:%d", "udp", 8053), "-l", "-P", "-n", "-Fnu")
	infoBuf.WriteString(fmt.Sprintf("%s\n", cmd.String()))
	buf, err := cmd.Output()
	if err != nil {

		// return 0, fmt.Errorf("%s: lsof error: %w", op, err)
	}
	infoBuf.WriteString(fmt.Sprintf("%s", string(buf)))
	splits := strings.Split(string(buf), "\n")
	var lastSeenUid string
	for _, split := range splits {
		split = strings.TrimSpace(split)
		if len(split) == 0 {
			continue
		}
		switch split[0] {
		case 'p':
		case 'u':
			lastSeenUid = split[1:] // remove the prefixed 'u' and get the user id
			infoBuf.WriteString(fmt.Sprintf("lastSeenUid: %s\n", lastSeenUid))
		case 'f':
		case 'n':
			srcdst := strings.Split(split[1:], "->")
			switch len(srcdst) {
			case 1:
				continue // listening
			case 2:
			default:
				continue
			}
			src := netip.MustParseAddrPort(srcdst[0])
			dst := netip.MustParseAddrPort(srcdst[1])
			infoBuf.WriteString(fmt.Sprintf("remote: %s\n", raddr.AddrPort().String()))
			infoBuf.WriteString(fmt.Sprintf("src %s\n", src.String()))
			infoBuf.WriteString(fmt.Sprintf("inAddr: %s\n", raddr.AddrPort().String()))
			infoBuf.WriteString(fmt.Sprintf("dst: %s:%d\n", dst.String(), dst.Port()))
			infoBuf.WriteString(fmt.Sprintf("listen: %s\n", localAddrPort.String()))
			infoBuf.WriteString(fmt.Sprintf("listenAddr: %s:%d\n", localAddrPort.Addr().String(), localAddrPort.Port()))
			// Verify dest is this service
			if dst.String() != localAddrPort.String() &&
				((localAddrPort.Addr() == netip.IPv4Unspecified() || localAddrPort.Addr() == netip.IPv6Unspecified()) && dst.Port() != localAddrPort.Port()) {
				continue
			}
			// Verify source is the incoming connection
			if src.String() != raddr.AddrPort().String() {
				continue
			}

			// YES!!!
			infoBuf.WriteString(fmt.Sprintf("found user: %s\n", lastSeenUid))
		default:
			return fmt.Errorf("%s: unexpected split line %s", op, split)
		}
	}
	if debug == "1" {
		cmd = exec.CommandContext(context.Background(), "sudo", "/usr/sbin/lsof", "-i", fmt.Sprintf("%s", "udp"), "-l", "-P", "-n")
		buf, err = cmd.Output()
		if err != nil {
			return fmt.Errorf("%s: lsof error: %w", op, err)
		}
		infoBuf.WriteString(fmt.Sprintf("%s\n", cmd.String()))
		infoBuf.WriteString(fmt.Sprintf("%s", string(buf)))

		cmd = exec.CommandContext(context.Background(), "sudo", "/usr/sbin/netstat", "-a", "-n", "-t", "-u", "-p", "udp", "-v")
		infoBuf.WriteString(fmt.Sprintf("%s\n", cmd.String()))
		buf, err = cmd.Output()
		if err != nil {
			return fmt.Errorf("%s: netstat error: %w", op, err)
		}
		splits = strings.Split(string(buf), "\n")
		// matchPort := fmt.Sprintf("%d", raddr.Port)
		for _, split := range splits {
			// if strings.Contains(split, matchPort) {
			infoBuf.WriteString(fmt.Sprintf("%s\n", split))
			// }
		}
	}
	return nil
}

func setUDPSocketOptions(conn *net.UDPConn) error {
	// Try setting the flags for both families and ignore the errors unless they
	// both error.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}
	return nil
}

// parseDstFromOOB takes oob data and returns the destination IP.
func parseDstFromOOB(oob []byte) net.IP {
	// Start with IPv6 and then fallback to IPv4
	// TODO(fastest963): Figure out a way to prefer one or the other. Looking at
	// the lvl of the header for a 0 or 41 isn't cross-platform.
	cm6 := new(ipv6.ControlMessage)
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return cm6.Dst
	}
	cm4 := new(ipv4.ControlMessage)
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return cm4.Dst
	}
	return nil
}

// correctSource takes oob data and returns new oob data with the Src equal to the Dst
func correctSource(oob []byte) []byte {
	dst := parseDstFromOOB(oob)
	if dst == nil {
		return nil
	}
	// If the dst is definitely an IPv6, then use ipv6's ControlMessage to
	// respond otherwise use ipv4's because ipv6's marshal ignores ipv4
	// addresses.
	if dst.To4() == nil {
		cm := new(ipv6.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	} else {
		cm := new(ipv4.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	}
	return oob
}
