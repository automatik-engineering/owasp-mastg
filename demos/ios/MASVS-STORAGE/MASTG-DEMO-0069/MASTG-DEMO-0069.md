---
platform: ios
title: References to APIs for Preventing Keyboard Caching of Text Fields with r2
id: MASTG-DEMO-0069
code: [swift]
test: MASTG-TEST-0x55-1
---

### Sample

The code snippet below creates multiple UI text inputs on the screen.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh` to find all attempts to set `UITextAutocorrectionTypeNo` attribute
3. Perform the same analysis for `secureTextEntry`.

{{ run.sh # textinputs.r2 }}

### Observation

{{ output.asm }}

The output reveals the use of [`setAutocorrectionType(.default)`](https://developer.apple.com/documentation/uikit/uitextinputtraits/autocorrectiontype) in the app. However, it doesn't look exactly the same as in `MastgTest.swift` because the compiler transforms some functions into Objective-C counterparts. An equivalent Objective-C representation in the binary looks like `objc_msgSend(void *address, "setAutocorrectionType:", 0)`. By looking at the output we can find this pattern at lines 31-36.

The third argument of `objc_msgSend(...)` is `UITextAutocorrectionType` because `x2` register at the time of the function invocation is set to `0` with a `mov` instruction at Line 33. `0` is a representation of [`UITextAutocorrectionTypeDefault`](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/default).

You can find all the possible values defined in UITextInputTraits.h by running (requires @MASTG-TOOL-0070):

```sh
grep UITextAutocorrectionType /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/UIKit.framework/Headers/UITextInputTraits.h

typedef NS_ENUM(NSInteger, UITextAutocorrectionType) {
    UITextAutocorrectionTypeDefault, # 0
    UITextAutocorrectionTypeNo, # 1
    UITextAutocorrectionTypeYes # 2
```

### Evaluation

The test fails because the output shows references to `setAutocorrectionType(.default)` for a text input collecting sensitive data.
