---
masvs_category: MASVS-STORAGE
platform: ios
title: App Sandbox Directories
---

On iOS, each application gets a sandboxed folder to store its data. As per the iOS security model, an application's sandboxed folder cannot be accessed by another application. Additionally, the users do not have direct access to the [iOS filesystem](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12), thus preventing browsing or extraction of data from the filesystem.

There are several ways to access the app's sandboxed folder:

- **On any device - Only Debug Builds**: You can use Xcode's Devices and Simulators window to download the app container.
- **On the iOS Simulator - All Built-in Apps and Debug Builds**: You can navigate to the app's sandboxed folder directly from the macOS filesystem.
- **On a non-jailbroken device - Only Repackaged Apps or Debug Apps**: You can use @MASTG-TECH-0090 and after that, use @MASTG-TOOL-0074 to explore the app's directory structure.
- **On a jailbroken device - All Apps**:
    - You can use SSH or a file explorer app to navigate the filesystem and access the sandboxed folder directly.
    - You can use @MASTG-TOOL-0074 to explore the app's directory structure.

## Application Folder Structure

The following illustration represents the application folder structure:

<img src="Images/Chapters/0x06a/iOS_Folder_Structure.png" width="400px" />

On iOS, system applications can be found in the `/Applications` directory while user-installed apps are available under `/private/var/containers/`. However, finding the right folder just by navigating the file system is not a trivial task as every app gets a random 128-bit UUID (Universal Unique Identifier) assigned for its directory names.

```txt
Bundle: /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67
Application: /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app
Data: /private/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693
```

As you can see, apps have two main locations:

- The Bundle directory (`/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/`).
- The Data directory (`/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/`).

These folders contain information that must be examined closely during application security assessments (for example when analyzing the stored data for sensitive data).

### Bundle directory

- **AppName.app**
    - This is the Application Bundle as seen in the IPA, it contains essential application data, static content as well as the application's compiled binary.
    - This directory is visible to users, but users can't write to it.
    - Content in this directory is not backed up.
    - The contents of this folder are used to validate the code signature.

### Data directory

- **Documents/**
    - Contains all the user-generated data. The application end user initiates the creation of this data.
    - Visible to users and users can write to it.
    - Content in this directory is backed up.
    - The app can disable paths by setting `NSURLIsExcludedFromBackupKey`.
- **Library/**
    - Contains all files that aren't user-specific, such as caches, preferences, cookies, and property list (plist) configuration files.
    - iOS apps usually use the `Application Support` and `Caches` subdirectories, but the app can create custom subdirectories.
- **Library/Caches/**
    - Contains semi-persistent cached files.
    - Invisible to users and users can't write to it.
    - Content in this directory is not backed up.
    - The OS may delete this directory's files automatically when the app is not running and storage space is running low.
- **Library/Application Support/**
    - Contains persistent files necessary for running the app.
    - Invisible to users and users can't write to it.
    - Content in this directory is backed up.
    - The app can disable paths by setting `NSURLIsExcludedFromBackupKey`.
- **Library/Preferences/**
    - Used for storing properties that can persist even after an application is restarted.
    - Information is saved, unencrypted, inside the application sandbox in a plist file called [BUNDLE_ID].plist.
    - All the key/value pairs stored using `NSUserDefaults` can be found in this file.
- **tmp/**
    - Use this directory to write temporary files that do not need to persist between app launches.
    - Contains non-persistent cached files.
    - Invisible to users.
    - Content in this directory is not backed up.
    - The OS may delete this directory's files automatically when the app is not running and storage space is running low.
