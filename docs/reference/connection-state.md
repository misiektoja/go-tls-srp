# Connection state

## ConnectionState

`Conn.ConnectionState()` describes a connection. Until the handshake has completed, every field
except `HandshakeComplete` is zero.

| Field or method | Content |
| --- | --- |
| `Version uint16` | Always `VersionTLS12` |
| `HandshakeComplete bool` | Whether the handshake has completed |
| `CipherSuite uint16` | The cipher suite in use, such as `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` |
| `ServerName string` | The SNI host name the client sent. On the client it is empty when `Config.ServerName` is empty or an IP address |
| `SRPUsername string` | The username the client proved it holds the password of. On the client it is `Config.Username` |
| `ExtendedMasterSecret bool` | Whether the connection used Extended Master Secret |
| `TLSUnique []byte` | The `tls-unique` channel binding, the client's 12-byte Finished message |
| `ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)` | RFC 5705 key material. Needs Extended Master Secret |

[Channel binding and Extended Master Secret](../guide/channel-binding.md) explains the last three.

## Conn

`*Conn` implements `net.Conn`.

| Method | Behavior |
| --- | --- |
| `Handshake() error` | Runs the handshake if it has not run. After a failure every call returns the stored error |
| `HandshakeContext(ctx context.Context) error` | Like `Handshake`. Canceling `ctx` during the handshake closes the connection and returns the context error. Later calls return the error of the closed connection. Once the handshake has completed, the context has no effect |
| `Read(b []byte) (int, error)` and `Write(b []byte) (int, error)` | Run the handshake first if needed |
| `Close() error` | Sends a `close_notify` alert when the handshake has completed and closes the connection |
| `CloseWrite() error` | Sends `close_notify` without closing the underlying connection. Fails before the handshake has completed |
| `SetDeadline`, `SetReadDeadline` and `SetWriteDeadline` | Set the deadlines of the underlying connection. After a write times out, every later write fails |
| `NetConn() net.Conn` | The underlying connection. Reading from it or writing to it corrupts the TLS connection |
| `LocalAddr()` and `RemoteAddr()` | The addresses of the underlying connection |

`Read` and `Write` call `Handshake`, so set a deadline for both before the first call when the
handshake has not run yet. Otherwise a silent peer blocks them indefinitely.

## Constants

| Constant | Value |
| --- | --- |
| `VersionTLS10` | `0x0301` |
| `VersionTLS11` | `0x0302` |
| `VersionTLS12` | `0x0303` |
| `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` | `0xC01A` |
| `TLS_SRP_SHA_WITH_AES_128_CBC_SHA` | `0xC01D` |
| `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` | `0xC020` |

`CipherSuiteName(id uint16) string` returns the name of a cipher suite ID.
