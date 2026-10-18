// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import "strconv"

// alert is a TLS alert description. Record layer errors carry it in a
// *net.OpError, with Op "local error" for an alert this server sent and
// "remote error" for one it received.
type alert uint8

const (
	// alert level
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify          alert = 0
	alertUnexpectedMessage    alert = 10
	alertBadRecordMAC         alert = 20
	alertRecordOverflow       alert = 22
	alertHandshakeFailure     alert = 40
	alertIllegalParameter     alert = 47
	alertDecodeError          alert = 50
	alertDecryptError         alert = 51
	alertProtocolVersion      alert = 70
	alertInsufficientSecurity alert = 71
	alertInternalError        alert = 80
	alertUserCanceled         alert = 90
	alertNoRenegotiation      alert = 100
	alertUnsupportedExtension alert = 110
	alertUnknownPSKIdentity   alert = 115
)

var alertText = map[alert]string{
	alertCloseNotify:          "close notify",
	alertUnexpectedMessage:    "unexpected message",
	alertBadRecordMAC:         "bad record MAC",
	alertRecordOverflow:       "record overflow",
	alertHandshakeFailure:     "handshake failure",
	alertIllegalParameter:     "illegal parameter",
	alertDecodeError:          "error decoding message",
	alertDecryptError:         "error decrypting message",
	alertProtocolVersion:      "protocol version not supported",
	alertInsufficientSecurity: "insufficient security level",
	alertInternalError:        "internal error",
	alertUserCanceled:         "user canceled",
	alertNoRenegotiation:      "no renegotiation",
	alertUnsupportedExtension: "unsupported extension",
	alertUnknownPSKIdentity:   "unknown PSK identity",
}

// String returns the alert's description, or its number if it has none.
func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return "tls: " + s
	}
	return "tls: alert(" + strconv.Itoa(int(e)) + ")"
}

// Error returns the alert's description.
func (e alert) Error() string {
	return e.String()
}
