class Burner < Formula
  desc "Throwaway Linux VMs on your own hardware"
  homepage "https://burnervm.dev"
  # the first release with the macOS port, set when it's tagged
  url "https://github.com/patrickhere/burner/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/patrickhere/burner.git", branch: "main"

  depends_on "rust" => :build
  # libkrun only runs guests on apple silicon
  depends_on arch: :arm64
  # mkfs.ext4 for each VM's scratch disk
  depends_on "e2fsprogs"
  depends_on "libkrun"
  depends_on macos: :sequoia

  def install
    ENV["LIBKRUN_LIB_DIR"] = Formula["libkrun"].opt_lib
    system "cargo", "install", *std_cargo_args(path: "burner")
    # hypervisor.framework only makes VMs for a binary signed with this entitlement
    system "codesign", "--force", "--sign", "-",
           "--entitlements", "dist/macos/burner.entitlements", bin/"burner"
  end

  def caveats
    <<~EOS
      burner needs a guest kernel and an image before it can boot anything.
      fetch both from the release that matches this burner, once:
        burner setup
      then burner doctor checks the rest. VMs run as you, no sudo.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/burner --version")
    assert_match "com.apple.security.hypervisor",
                 shell_output("codesign -d --entitlements - --xml #{bin}/burner 2>/dev/null")
    assert_match "https:// or file://", shell_output("#{bin}/burner setup --from ftp://example.com 2>&1", 1)
  end
end
