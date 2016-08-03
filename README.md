# u2f [![GoDoc](https://godoc.org/github.com/flynn/u2f?status.svg)](https://godoc.org/github.com/flynn/u2f)

This is a set of Go packages that implement communication with [FIDO
U2F](https://fidoalliance.org/specifications/overview/) tokens over USB. See
[the documentation](https://godoc.org/github.com/flynn/u2f) and `example`
directories in each package for usage information.

## Compatibility

Tested with these devices on macOS, Linux, and Windows:

| Vendor | Product | Vendor ID | Product ID | Version | Implements Wink | Notes |
| ------ | ------- | --------- | ---------- | ------- | --------------- | ----- |
| Yubico | Security Key | 0x1050 | 0x0120 | 3.33 | No | White LED-backlit key icon on button. |
| Yubico | Security Key | 0x1050 | 0x0120 | 4.18 | Yes | Green LED-backlit "y" icon on button, GitHub silkscreen on back. |
| Yubico | Yubikey 4 | 0x1050 | 0x0406 | 4.26 | Yes | |
| Yubico | Yubikey NEO-n | 0x1050 | 0x0115 | 3.42 | No | |
| Plug-up | Security Key | 0x2581 | 0xf1d0 | 0.01 | No | |
| Feitian | ePass FIDO | 0x096e | 0x0850 | 11.03 | Yes | |
| Hypersecu | HyperFIDO | 0x096e | 0x0880 | 10.05 | Yes | Appears to made by Feitian. |
| NEOWAVE | Keydo | 0x1e0d | 0xf1d0 | 1.00 | Yes | |

On Linux, installation of [udev
rules](https://github.com/Yubico/libu2f-host/blob/master/70-u2f.rules) is
required.
