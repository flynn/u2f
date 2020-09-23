# Device selection

When multiple authenticators are available, the webauthn specification isn't really clear how to proceed (see for example https://www.w3.org/TR/webauthn/#createCredential, starting at bullet point 19). Some browsers doesn't even support CTAP2 and rely exclusively on CTAP1/U2F protocol, thus making it impossible to use webauthn with user verification in required mode, or they downgrade the preferred mode to behave like the discouraged one, like Firefox 80.0.1 under Linux. 
However, Windows browsers seem to offer a better support for CTAP2, and the following flow have been observed:

```
List all available devices
For each devices:
    Depending on User Verification:
        Discouraged:
            > Select devices with either CTAP1 or CTAP2 with clientPin = false (exclude CTAP2 devices with clientPin = true)
            > For all selected devices
                > Send request to all devices, on first success response cancel all others
                    > On all errors, return error
        Preferred:
            > Select all CTAP1 and CTAP2 devices
            > If multiple devices selected
                > Blink all devices waiting for user presence, this will select the device to use
            > If user selected a CTAP2 device with clientPin = false
                > Guide user to set new pin.
            > else if user selected a CTAP2 device with clientPin = true
                > Request user PIN
            > Send request to selected device with optional PIN if just set or requested
        Required:
            > Select devices with CTAP2 support
            > If multiple CTAP2 devices selected
                > Blink all devices waiting for user presence, this will select the device to use
                > If user selected a device with clientPin = false
                    > Guide user to set new pin.
                > Send request to selected device with PIN
```
