import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.title = "Encounter"
    self.minSize = NSSize(width: 640, height: 480)

    RegisterGeneratedPlugins(registry: flutterViewController)

    if #available(macOS 11.0, *) {
      let toolbar = NSToolbar(identifier: NSToolbar.Identifier("EncounterMainToolbar"))
      toolbar.displayMode = .iconOnly
      self.toolbar = toolbar
      self.toolbarStyle = .unified
    }

    super.awakeFromNib()
  }
}
