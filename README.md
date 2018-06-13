# u2f [![GoDoc](https://godoc.org/github.com/flynn/u2f?status.svg)](https://godoc.org/github.com/flynn/u2f)

This is a set of Go packages that implement communication with [FIDO
U2F](https://fidoalliance.org/specifications/overview/) tokens over USB. See
[the documentation](https://godoc.org/github.com/flynn/u2f) and `example`
directories in each package for usage information.

## Compatibility

Tested with these devices on macOS, Linux, and Windows:

| Vendor | Product | Vendor ID | Product ID | Version | Implements Wink | Notes |
| ------ | ------- | --------- | ---------- | ------- | --------------- | ----- |
| Feitian | FIDO K2 | 0x096e | 0x0850 | 11.03 | Yes | Also known as Feitian ePass FIDO. |
| Feitian | FIDO K6 | 0x096e | 0x0850 | 11.03 | Yes | Also known as Feitian ePass FIDO Agile 2. |
| Feitian | MultiPass FIDO | 0x096e | 0x085a | 32.06 | Yes | |
| Hypersecu | HyperFIDO U2F Security Key | 0x096e | 0x0880 | 10.05 | Yes | Also known as Feitian FIDO K5. |
| NEOWAVE | Keydo | 0x1e0d | 0xf1d0 | 1.00 | Yes | |
| Plug-up | Security Key | 0x2581 | 0xf1d0 | 0.01 | No | |
| SatoshiLabs | Bitcoin Wallet [TREZOR] | 0x534c | 0x0001 | 1.6.0 | ? | Tested on Linux |
| SecureMetric | IDENOS | 0x096e | 0x0850 | 10.05 | Yes | Also known as Feitian FIDO K4. |
| Yubico | FIDO U2F Security Key | 0x1050 | 0x0120 | 3.33 | No | White LED-backlit key icon on button. |
| Yubico | Special Edition Octocat Security Key | 0x1050 | 0x0120 | 4.18 | Yes | Green LED-backlit "y" icon on button, GitHub Octocat logo on the back. |
| Yubico | Yubikey 4 | 0x1050 | 0x0406 | 4.26 | Yes | |
| Yubico | Yubikey NEO-n | 0x1050 | 0x0115 | 3.42 | No | |

On Linux, installation of [udev
rules](https://github.com/Yubico/libu2f-host/blob/master/70-u2f.rules) is
required.
