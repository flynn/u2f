# u2f [![GoDoc](https://godoc.org/github.com/flynn/u2f?status.svg)](https://godoc.org/github.com/flynn/u2f)

This is a set of Go packages that implement communication with [FIDO
U2F](https://fidoalliance.org/specifications/overview/) tokens over USB. See
[the documentation](https://godoc.org/github.com/flynn/u2f) and `example`
directories in each package for usage information.

## Compatibility

Tested with these devices on Linux and macOS:

| Vendor | Product | Vendor ID | Product ID | Version | Notes |
| ------ | ------- | --------- | ---------- | ------- | ----- |
| Yubico | Security Key | 0x1050 | 0x0120 | 3.33 | White LED-backlit key icon on button. |
| Yubico | Security Key | 0x1050 | 0x0120 | 4.18 | Green LED-backlit "y" icon on button, GitHub silkscreen on back. |
| Yubico | Yubikey 4 | 0x1050 | 0x0406 | 4.26 | |
| Yubico | Yubikey NEO-n | 0x1050 | 0x0115 | 3.42 | |
| Plug-up | Security Key | 0x2581 | 0xf1d0 | 0.01 | |
| Feitian | ePass FIDO | 0x096e | 0x0850 | 11.03 | Registration test of user presence is flaky, more testing/debugging is required. |
| Hypersecu | HyperFIDO | 0x096e | 0x0880 | 10.05 | Appears to made by Feitian. |

On Linux, installation of [udev
rules](https://github.com/Yubico/libu2f-host/blob/master/70-u2f.rules) is
required.
