---
platform: ios
title: Keyboard Caching Not Prevented for Sensitive Data with r2
id: MASTG-DEMO-0076
code: [swift]
test: MASTG-TEST-0313
---

### Sample

The code snippet below creates multiple UI text inputs on the screen.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh` to find all attempts to set the `UITextAutocorrectionTypeNo` attribute.
3. Perform the same analysis for `secureTextEntry`.

{{ run.sh # textinputs.r2 }}

### Observation

The output reveals:

- 2 calls to `setAutocorrectionType(...)` at `0x10000455c` and `0x1000045c8`.
- 1 call to `setSecureTextEntry(...)` at `0x100004638`.

{{ output.asm }}

### Evaluation

The test fails because the static analysis reveals a text field configured with [`setAutocorrectionType(.default)`](https://developer.apple.com/documentation/uikit/uitextinputtraits/autocorrectiontype), which allows sensitive data to be cached by the keyboard.

**Interpreting the Disassembly:**

Although MastgTest.swift is written in Swift, it interacts with UIKit (an Objective-C framework). The compiler translates these interactions into calls to the `objc_msgSend` function. We analyze the arguments passed to this function using the ARM64 calling convention:

- `x0` register: holds `self` (the instance of the UITextField).
- `x1` register: holds the selector (the method name).
- `x2` register: holds the argument passed to that method.

**1. Cache enabled (FAIL):**

At address `0x10000455c`, the binary loads the selector `setAutocorrectionType:`.

Immediately after, at address `0x100004564`, the instruction `mov x2, 0` sets the argument to `0`.

According to UITextInputTraits.h, `0` corresponds to [`UITextAutocorrectionTypeDefault`](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/default) (the following command requires @MASTG-TOOL-0070 and macOS):

```sh
grep UITextAutocorrectionType /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/UIKit.framework/Headers/UITextInputTraits.h

typedef NS_ENUM(NSInteger, UITextAutocorrectionType) {
    UITextAutocorrectionTypeDefault, # 0
    UITextAutocorrectionTypeNo, # 1
    UITextAutocorrectionTypeYes # 2
```

Alternatively, you can view the full UITextInputTraits.h header online in public SDK mirrors on GitHub such as [GitHub - xybp888/iOS-SDKs](https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS18.4.sdk/System/Library/Frameworks/UIKit.framework/Headers/UITextInputTraits.h#L37-L41).

This confirms that for the input field labeled `"Caching input"` (placeholder string constructed at `0x100004514`), the **app explicitly allows the default behavior, enabling the keyboard cache**.

**2. Cache disabled (PASS):**

Conversely, for the `"Non-caching input"` field, the selector is loaded at `0x1000045c8`. The argument is set at `0x1000045d0` via `mov w2, 1`. The value `1` represents `UITextAutocorrectionTypeNo`, which correctly prevents keyboard caching.

**3. Password field (PASS):**

Finally, the logic for the password field begins around `0x1000045e8`.

The selector `setSecureTextEntry:` is loaded at address `0x100004638`.

The argument is set to `1` (true) at address `0x100004640` (`mov w2, 1`).

This confirms that [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry/) is enabled for the third field, which provides the highest level of security by masking characters and disabling the cache.
