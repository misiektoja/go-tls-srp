# Configuration

## Config

One `Config` type serves both sides. Some fields apply to one side only. Do not change a `Config`
after passing it to a function of the package. A `Config` may be reused for many connections.

| Field | Side | Default | Rules |
| --- | --- | --- | --- |
| `GetVerifier func(*ClientHelloInfo) (*Verifier, error)` | Server | None, required | See [Running a server](../guide/server.md#the-getverifier-callback) |
| `Username string` | Client | None, required | 1 to 255 bytes, hashed as given without SASLprep |
| `Password string` | Client | Empty | Hashed as given without SASLprep |
| `ServerName string` | Client | Empty, no SNI | A trailing dot is removed. An IP address is not sent |
| `MinGroupBits int` | Client | 2048 when zero | 0 to 8192. Groups with a smaller prime are refused |
| `CipherSuites []uint16` | Both | AES-256, then AES-128 when nil | The preference order. See [Cipher suites](../guide/cipher-suites.md) |
| `Rand io.Reader` | Both | `crypto/rand` when nil | Source of the random values and the SRP exponents |
| `KeyLogWriter io.Writer` | Both | None | Receives the master secrets in NSS key log format. For debugging only |

A client `Config` that breaks these rules fails the handshake before anything is sent. `Server` and
`NewListener` need a non-nil `Config`. The server handshake checks only that `GetVerifier` is set.

## ClientHelloInfo

The argument of `GetVerifier`.

| Field or method | Content |
| --- | --- |
| `Username string` | The SRP username, as sent. 1 to 255 bytes, possibly not valid UTF-8 |
| `ServerName string` | The SNI host name. Empty when the client sent none |
| `CipherSuites []uint16` | The cipher suites the client offered |
| `Conn net.Conn` | The underlying connection. Reading from it or writing to it breaks the handshake |
| `Context() context.Context` | A child of the context passed to `HandshakeContext`, canceled when the handshake ends |

## Constructors

| Function | Returns |
| --- | --- |
| `Client(conn net.Conn, config *Config) *Conn` | A client connection over `conn` |
| `Server(conn net.Conn, config *Config) *Conn` | A server connection over `conn` |
| `Listen(network, laddr string, config *Config) (net.Listener, error)` | A listener from `net.Listen` whose connections are `*Conn`. Fails when `GetVerifier` is not set |
| `NewListener(inner net.Listener, config *Config) net.Listener` | `inner` with each accepted connection wrapped in `Server` |

## Verifiers and groups

| Function or method | Purpose |
| --- | --- |
| `NewVerifier(group *Group, username, password, salt []byte) (*Verifier, error)` | Computes a verifier. The username must be 1 to 255 bytes |
| `NewSalt(rand io.Reader) ([]byte, error)` | 20 random bytes whose first byte is not zero |
| `SimulatedVerifier(seed []byte, group *Group, username []byte) *Verifier` | A stable fake verifier for an unknown username |
| `(*Verifier).Validate() error` | Checks the group, a salt of 1 to 255 bytes and a value that is not zero and below `N` |
| `GroupByBits(bits int) (*Group, error)` | The RFC 5054 group of that prime size |
| `GroupByParameters(n, g []byte) (*Group, error)` | The RFC 5054 group with that prime and generator |
| `(*Group).Bits() int`, `N() []byte`, `Generator() []byte` | The prime size and copies of the prime and the generator |

[Verifiers and groups](../guide/verifiers.md) explains how to use them.
