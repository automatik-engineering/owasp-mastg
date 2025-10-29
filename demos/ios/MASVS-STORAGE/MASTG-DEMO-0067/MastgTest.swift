import SwiftUI
import os
import Darwin

struct MastgTest {
  
  static func mastgTest(completion: @escaping (String) -> Void) {
    let filename = "secret.json"
    let secret = "secret_token"
    
    let fm = FileManager.default
    
    let types: [FileManager.SearchPathDirectory] = [
        .documentDirectory,
        .cachesDirectory,
        .libraryDirectory,
        .applicationSupportDirectory,
    ]
    
    for type in types{
      guard let docDir = fm.urls(for: type, in: .userDomainMask).first else { continue }
      do{
        try secret.write(to: docDir.appendingPathExtension(filename), atomically: true, encoding: .utf8)
        print("Success \(docDir.appending(components: filename).path())")
      } catch {
        print("Failed to store file: \(error.localizedDescription)")
      }
    }
    completion("Successfully stored files to the storage")
  }
}
