# Verifiers and groups

## What a verifier is

A `Verifier` is the stored SRP record of one username:

| Field | Content |
| --- | --- |
| `Group` | One of the seven RFC 5054 groups |
| `Salt` | 1 to 255 bytes, sent to the client exactly as stored |
| `Value` | `v = g^x mod N` in big-endian bytes, with or without leading zeros |

`NewVerifier` computes it as
[RFC 5054, Section 2.4](https://www.rfc-editor.org/rfc/rfc5054#section-2.4) specifies:
`x = SHA1(s | SHA1(I | ":" | P))` and `v = g^x mod N`. The username `I` and the password `P` are
hashed as given, without SASLprep, as OpenSSL does.

The server needs no password. A verifier is still sensitive: whoever reads it can test password
guesses offline and can pose as the server to that user
([RFC 5054, Section 3.3](https://www.rfc-editor.org/rfc/rfc5054#section-3.3)). Protect stored
verifiers like password hashes.

## Creating a verifier

```go
--8<-- "example_test.go:verifier"
```

`NewSalt` returns 20 random bytes whose first byte is not zero. OpenSSL clients read the salt as a
number and drop leading zero bytes, so a salt that starts with zero would give them another `x` and
the handshake would fail like a wrong password. `NewVerifier` accepts any salt of 1 to 255 bytes, so
use `NewSalt` unless you have a reason not to. The username must be 1 to 255 bytes.

## Storing and loading verifiers

Store the username, the group size, the salt and the value. To load a record, look the group up with
`GroupByBits` and fill in the fields:

```go
group, err := srptls.GroupByBits(record.GroupBits)
if err != nil {
	return nil, err
}
v := &srptls.Verifier{Group: group, Salt: record.Salt, Value: record.Value}
if err := v.Validate(); err != nil {
	return nil, err
}
```

`Validate` checks that the verifier has an RFC 5054 group, a salt of 1 to 255 bytes and a value that is
not zero and is below `N`. The server runs the same check on every verifier `GetVerifier` returns and
ends the handshake with an `internal_error` alert when it fails. Calling `Validate` when you load a
record finds a damaged record earlier, with a clearer error.

The verifier only works with the group it was made in. Changing a user's group or password means
creating a new verifier from the password.

## Groups

The package has the seven groups of
[RFC 5054, Appendix A](https://www.rfc-editor.org/rfc/rfc5054#appendix-A) and no way to define
another, because OpenSSL clients accept only these.

| Prime size in bits | Generator |
| --- | --- |
| 1024 | 2 |
| 1536 | 2 |
| 2048 | 2 |
| 3072 | 5 |
| 4096 | 5 |
| 6144 | 5 |
| 8192 | 19 |

* `GroupByBits` returns the group with a prime of the given size.
* `GroupByParameters` returns the group whose prime and generator match the given big-endian bytes.
  Leading zero bytes are ignored.
* `Group.Bits`, `Group.N` and `Group.Generator` return the size, a copy of the prime and a copy of the
  generator.

The server sends the group of each user's verifier. The client accepts 2048 bits and more unless its
`MinGroupBits` allows the smaller groups. A larger group costs both sides more per handshake, roughly
with the square of the prime size.

## Importing OpenSSL verifier files

`openssl srp` stores users in a text file, the srpvfile, that `openssl s_server -srpvfile` reads.
Each user is one line of tab-separated fields: the entry type, the verifier, the salt, the username,
the group and an info field. Only lines of type `V` hold valid users.

The verifier and the salt are numbers written in OpenSSL's own base 64 alphabet, not standard
base 64. For the groups OpenSSL ships, the group field is the prime size in bits. This code reads one
line, decodes both numbers to big-endian bytes without leading zeros and builds a `Verifier`:

```go
--8<-- "example_test.go:srpvfile"
```

It is `Example_openSSLVerifierFile` in `example_test.go`, which signs in with the password the line
was made from. Dropping leading zero bytes from the salt matters: OpenSSL computes `x` from the salt as
a number, so a salt imported with a leading zero byte would fail like a wrong password.
