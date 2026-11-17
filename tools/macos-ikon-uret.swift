// macOS simgelerini assets/icons/src/*.svg çizimlerinden üretir (tek seferlik; sonuçlar commit'lenir).
// Kullanım (repo kökünde): swiftc -O tools/macos-ikon-uret.swift -o /tmp/ikon && /tmp/ikon
//   assets/macos/{acik,kapali,sorun}.png         menü çubuğu, 36 px (18 pt @2x)
//   assets/macos/{acik,kapali,sorun}-portre.png  menü başlığı, 256 px (128 pt @2x, Windows menüsündeki boyut)
//   assets/macos/SONdpi.icns                      uygulama simgesi (iconutil ile)
import AppKit

func render(_ svg: String, _ px: Int, _ out: String) {
    guard let img = NSImage(contentsOfFile: svg) else { fatalError("okunamadı: \(svg)") }
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    ctx.imageInterpolation = .high
    NSGraphicsContext.current = ctx
    img.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
    NSGraphicsContext.restoreGraphicsState()
    try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
}

let src = "assets/icons/src"
let dst = "assets/macos"
try! FileManager.default.createDirectory(atPath: dst, withIntermediateDirectories: true)
for s in ["acik", "kapali", "sorun"] {
    render("\(src)/\(s)-kucuk.svg", 36, "\(dst)/\(s).png")
    render("\(src)/\(s)-portre.svg", 256, "\(dst)/\(s)-portre.png")
}
let iconset = NSTemporaryDirectory() + "SONdpi.iconset"
try? FileManager.default.removeItem(atPath: iconset)
try! FileManager.default.createDirectory(atPath: iconset, withIntermediateDirectories: true)
for (pt, scale) in [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)] {
    let name = scale == 1 ? "icon_\(pt)x\(pt).png" : "icon_\(pt)x\(pt)@2x.png"
    let svg = pt * scale <= 32 ? "\(src)/acik-kucuk.svg" : "\(src)/acik-ayrintili.svg"
    render(svg, pt * scale, "\(iconset)/\(name)")
}
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconset, "-o", "\(dst)/SONdpi.icns"]
try! p.run()
p.waitUntilExit()
print(p.terminationStatus == 0 ? "tamam" : "iconutil hata \(p.terminationStatus)")
