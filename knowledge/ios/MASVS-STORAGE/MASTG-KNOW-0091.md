---
masvs_category: MASVS-STORAGE
platform: ios
title: File System APIs
---

iOS apps can write data to the file system through the Foundation and lower-level POSIX interfaces. The primary API is [`FileManager`](https://developer.apple.com/documentation/foundation/filemanager), which provides methods to create, read, and remove files. Files should be stored in app-specific directories determined using `FileManager.default.urls(for:in:)` typically under the [userDomainMask](https://developer.apple.com/documentation/foundation/filemanager/searchpathdomainmask/userdomainmask), such as:

- [Documents](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/documentdirectory)
- [Library](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/librarydirectory)
- [Caches](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/cachesdirectory)
- [Application Support](https://developer.apple.com/documentation/foundation/filemanager/searchpathdirectory/applicationsupportdirectory) directories.

A file can be created and written to using [`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)). File protection attributes, such as [`FileProtectionType.complete`](https://developer.apple.com/documentation/foundation/fileprotectiontype/complete), ensure that data remains encrypted while the device is locked, as described in Apple's [Encrypting Your App's Files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files).

Example:

```swift
FileManager.default.createFile(
    atPath: filePath,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

In addition to file creation, data can be written to existing files using various APIs, including:

- [`Data.write(to:options:)`](https://developer.apple.com/documentation/foundation/nsdata/write(tofile:options:)) and [`String.write(to:)`](https://developer.apple.com/documentation/swift/string/write(to:)) for direct file writes.
- [`FileHandle.write(contentsOf:)`](https://developer.apple.com/documentation/foundation/filehandle/write(contentsof:)) for streamed or incremental writing.
- POSIX APIs (`open`, `write`, `pwrite`, `close`) for low-level file access.

For more documentation, see [Apple Developer: File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/).

Other ways to store data that do not involve direct file system access include (but are not limited to):

- @MASTG-KNOW-0092
- @MASTG-KNOW-0093
- @MASTG-KNOW-0094
- @MASTG-KNOW-0096
- @MASTG-KNOW-0097
- @MASTG-KNOW-0075
