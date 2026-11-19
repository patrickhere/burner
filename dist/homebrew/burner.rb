class Burner < Formula
  desc "Throwaway Linux VMs on your own hardware"
  homepage "https://burnervm.dev"
  # the first release with the macOS port. at release, tools/formula-shas TAG
  # COMMIT prints the urls and the three sha256s for this file, each checked
  # against the tagged commit or the release's build provenance, not taken
  # from what github serves
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

  # what burner setup installs. pinned here in the tap, so assets swapped on
  # the release afterwards don't get past brew. the kernel is the one
  # install.sh pins
  resource "guest-kernel" do
    url "https://github.com/patrickhere/burner/releases/download/v0.2.0/vmlinux-aarch64",
        using: :nounzip
    sha256 "7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4"
  end

  resource "alpine-image" do
    url "https://github.com/patrickhere/burner/releases/download/v0.2.0/alpine-aarch64.ext4.gz",
        using: :nounzip
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    # libkrun is the VM boundary. homebrew can't put a version bound on a
    # dependency, so the oldest one burner was tested with is checked here
    # (burner doctor warns about an older one too)
    libkrun_min = Version.new("1.19.0")
    if Formula["libkrun"].version < libkrun_min
      odie "burner needs libkrun #{libkrun_min} or newer: brew upgrade libkrun"
    end
    ENV["LIBKRUN_LIB_DIR"] = formula_opt_lib("libkrun")
    system "cargo", "install", *std_cargo_args(path: "burner")
    # hypervisor.framework only makes VMs for a binary signed with this entitlement
    system "codesign", "--force", "--sign", "-",
           "--entitlements", "dist/macos/burner.entitlements", bin/"burner"
    resource("guest-kernel").stage { pkgshare.install "vmlinux-aarch64" }
    resource("alpine-image").stage { pkgshare.install "alpine-aarch64.ext4.gz" }
  end

  def caveats
    <<~EOS
      burner needs a guest kernel and an image before it can boot anything.
      this formula fetched both, install them once:
        burner setup
      then burner doctor checks the rest. VMs run as you, no sudo.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/burner --version")
    assert_match "com.apple.security.hypervisor",
                 shell_output("codesign -d --entitlements - --xml #{bin}/burner 2>/dev/null")
    assert_match "https:// or file://", shell_output("#{bin}/burner setup --from ftp://example.com 2>&1", 1)
    assert_path_exists pkgshare/"vmlinux-aarch64"
    assert_path_exists pkgshare/"alpine-aarch64.ext4.gz"
  end
end
