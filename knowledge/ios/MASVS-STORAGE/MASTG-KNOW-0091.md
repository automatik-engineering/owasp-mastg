---
masvs_category: MASVS-STORAGE
platform: ios
title: File System APIs
---

iOS apps can write data to the file system [using various APIs](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively), depending on the use case.

For internal app files, caches, exports, or simple background writes where you the app fully owns the path and conflicts are unlikely, apps typically use [`FileManager`](https://developer.apple.com/documentation/foundation/filemanager).

A file can be created and written to with `FileManager` using [`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)).

- First, obtain the path using [`FileManager.default.urls(for:in:)`](https://developer.apple.com/documentation/foundation/filemanager/urls(for:in:)). Use the `for` parameter to specify the directory, such as: [.documentDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory), [.libraryDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/librarydirectory), [.cachesDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/cachesdirectory), [.applicationSupportDirectory](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/applicationsupportdirectory) directories.
- Next, call `createFile(atPath:contents:attributes:)`, providing the file path, data to write (as `Data`), and optional attributes (such as file protection level).

Example:

```swift
let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("filename.txt")
FileManager.default.createFile(
    atPath: url.path,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

Alternatively, you can write data to files using other APIs, including:

- [`Data.write(to:options:)`](https://developer.apple.com/documentation/foundation/nsdata/write(tofile:options:)) and [`String.write(to:)`](https://developer.apple.com/documentation/swift/string/write(to:)) for direct file writes.
- [`FileHandle.write(contentsOf:)`](https://developer.apple.com/documentation/foundation/filehandle/write(contentsof:)) for streamed or incremental writing.
- POSIX APIs (`open`, `write`, `pwrite`, `close`) for low-level file access.

There are other cases, document-based apps, where users are expected to open and save files, when the system should coordinate access, when iCloud or Files app integration is needed, or when autosave and versioning matter. In these cases, apps can use [`UIDocument`](https://developer.apple.com/documentation/uikit/uidocument) or [`NSDocument`](https://developer.apple.com/documentation/AppKit/NSDocument).

## Data Protection

File protection attributes, such as [`FileProtectionType.complete`](https://developer.apple.com/documentation/foundation/fileprotectiontype/complete), ensure that data remains encrypted while the device is locked, as described in Apple's [Encrypting Your App's Files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files).

The default file protection level is `NSFileProtectionType.completeUntilFirstUserAuthentication` and can be modified using the `attributes` parameter when creating a file using [`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)) or later using [`setAttributes(_:ofItemAtPath:)`](https://developer.apple.com/documentation/foundation/filemanager/setattributes(_:ofitematpath:)).

Note that files created using other APIs inherit the default file protection level unless explicitly set using [`setAttributes(_:ofItemAtPath:)`](https://developer.apple.com/documentation/foundation/filemanager/setattributes(_:ofitematpath:)). For example:

```swift
FileManager.default.setAttributes(
    [FileAttributeKey.protectionKey: FileProtectionType.complete],
    ofItemAtPath: path
)
```

For more information, see:
- [Using the File System Effectively](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively)
- [Apple Developer: File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/).

Other ways to store data that do not involve direct file system access include (but are not limited to):

- @MASTG-KNOW-0092
- @MASTG-KNOW-0093
- @MASTG-KNOW-0094
- @MASTG-KNOW-0096
- @MASTG-KNOW-0097
- @MASTG-KNOW-0075
