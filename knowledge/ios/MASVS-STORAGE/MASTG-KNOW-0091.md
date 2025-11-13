---
masvs_category: MASVS-STORAGE
platform: ios
title: File System APIs
---

iOS apps can write data to the file system [using various APIs](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively), depending on the use case.

For internal app files, caches, exports, or simple background writes where the app fully controls the path and conflicts are unlikely, apps typically use [`FileManager`](https://developer.apple.com/documentation/foundation/filemanager).

A file can be created and written using `FileManager` and [`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)).

- First, obtain the path using [`FileManager.default.urls(for:in:)`](https://developer.apple.com/documentation/foundation/filemanager/urls(for:in:)). Use the `for` parameter to specify the directory, such as [.documentDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory), [.libraryDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/librarydirectory), [.cachesDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/cachesdirectory), or [.applicationSupportDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/applicationsupportdirectory).
- Next, call `createFile(atPath:contents:attributes:)`, providing the path, the data to write, and optional attributes such as the file protection level.

Example:

```swift
let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("filename.txt")
FileManager.default.createFile(
    atPath: url.path,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

Other APIs can write to files as well, including:

- [`Data.write(to:options:)`](https://developer.apple.com/documentation/foundation/nsdata/write(tofile:options:)) and [`String.write(to:)`](https://developer.apple.com/documentation/swift/string/write(to:))
- [`FileHandle.write(contentsOf:)`](https://developer.apple.com/documentation/foundation/filehandle/write(contentsof:)) for incremental writes
- POSIX APIs such as `open`, `write`, `pwrite`, and `close` for low level access

In document based apps, where the system should coordinate access, integrate with iCloud or the Files app, or support autosave and versioning, developers can use [`UIDocument`](https://developer.apple.com/documentation/uikit/uidocument) or [`NSDocument`](https://developer.apple.com/documentation/AppKit/NSDocument).

## Data Protection

File protection attributes such as [`FileProtectionType.complete`](https://developer.apple.com/documentation/foundation/fileprotectiontype/complete) ensure that data remains encrypted while the device is locked, as described in Apple's [Encrypting Your App's Files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files).

The default protection level is `NSFileProtectionCompleteUntilFirstUserAuthentication` and can be changed by supplying attributes when creating a file with [`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)) or later using [`setAttributes(_:ofItemAtPath:)`](https://developer.apple.com/documentation/foundation/filemanager/setattributes(_:ofitematpath:)).

Files created using other APIs inherit the default protection level unless explicitly updated with `setAttributes`. For example:

```swift
FileManager.default.setAttributes(
    [FileAttributeKey.protectionKey: FileProtectionType.complete],
    ofItemAtPath: path
)
```

For more information, see:
- [Using the File System Effectively](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively)
- [File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)

Other ways to store data that do not involve direct file system access include:

- @MASTG-KNOW-0092
- @MASTG-KNOW-0093
- @MASTG-KNOW-0094
- @MASTG-KNOW-0096
- @MASTG-KNOW-0097
- @MASTG-KNOW-0075
