class Burner < Formula
  desc "Throwaway Linux VMs on your own hardware"
  homepage "https://burnervm.dev"
  # burner and burner-tui as the release workflow built them for apple
  # silicon, so installing doesn't need rust. at release, tools/formula-shas
  # TAG COMMIT prints the urls and the four sha256s for this file, each
  # checked against the release's build provenance or the tagged commit, not
  # taken from what github serves
  url "https://github.com/patrickhere/burner/releases/download/v0.3.1/burner-v0.3.1-aarch64-macos.tar.gz"
  version "0.3.1"
  sha256 "516247efb833a2cc12f281be0f6394358c10c1329c5ae7a1fec5ab4187ad29cd"
  license any_of: ["MIT", "Apache-2.0"]

  head do
    url "https://github.com/patrickhere/burner.git", branch: "main"
    depends_on "rust" => :build
  end

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
    url "https://github.com/patrickhere/burner/releases/download/v0.3.1/vmlinux-aarch64",
        using: :nounzip
    sha256 "7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4"
  end

  resource "alpine-image" do
    url "https://github.com/patrickhere/burner/releases/download/v0.3.1/alpine-aarch64.ext4.gz",
        using: :nounzip
    sha256 "215a83d2950d3e778e0cc9f00d5f51abd9d43ad8f7e16e882595958ea762aa72"
  end

  def install
    # libkrun is the VM boundary. homebrew can't put a version bound on a
    # dependency, so the oldest one burner was tested with is checked here
    # (burner doctor warns about an older one too)
    libkrun_min = Version.new("1.19.0")
    if Formula["libkrun"].version < libkrun_min
      odie "burner needs libkrun #{libkrun_min} or newer: brew upgrade libkrun"
    end
    libkrun = "#{formula_opt_lib("libkrun")}/libkrun.1.dylib"
    if build.head?
      ENV["LIBKRUN_LIB_DIR"] = formula_opt_lib("libkrun")
      system "cargo", "install", *std_cargo_args(path: "burner")
      entitlements = "dist/macos/burner.entitlements"
    else
      bin.install "burner", "burner-tui"
      entitlements = "burner.entitlements"
      # built against libkrun in /opt/homebrew, brew's prefix on apple silicon
      built = "/opt/homebrew/opt/libkrun/lib/libkrun.1.dylib"
      system "install_name_tool", "-change", built, libkrun, bin/"burner" if built != libkrun
    end
    # hypervisor.framework only makes VMs for a binary signed with this entitlement
    system "codesign", "--force", "--sign", "-", "--entitlements", entitlements, bin/"burner"
    # completions and man pages from burner's own command line, so they
    # always have this version's flags
    generate_completions_from_executable(bin/"burner", "completions")
    system bin/"burner", "__man", buildpath/"man"
    man1.install Dir[buildpath/"man/*.1"]
    resource("guest-kernel").stage { pkgshare.install "vmlinux-aarch64" }
    resource("alpine-image").stage { pkgshare.install "alpine-aarch64.ext4.gz" }
    # the debian image isn't fetched here, so brew install doesn't download it
    # for everyone. it's pinned all the same: burner setup debian fetches it
    # from the release and checks it against this
    (pkgshare/"pins").write "fe80f8060075006c33b48b757d9e7efd4971b39581aab5a39da385362825d0a7  " \
                            "debian-aarch64.ext4.gz\n"
  end

  def caveats
    <<~EOS
      burner needs a guest kernel and an image before it can boot anything.
      this formula fetched the kernel and the alpine image, install them once:
        burner setup
      burner setup debian fetches the debian image too.
      then burner doctor checks the rest. VMs run as you, no sudo.
      after every brew upgrade burner, run burner setup again (and burner
      setup debian if you have it): the images go with the burner they came with.
      to remove it all: burner setup --remove, then brew uninstall burner.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/burner --version")
    assert_match version.to_s, shell_output("#{bin}/burner-tui --version") unless build.head?
    assert_match "com.apple.security.hypervisor",
                 shell_output("codesign -d --entitlements - --xml #{bin}/burner 2>/dev/null")
    assert_match "https:// or file://", shell_output("#{bin}/burner setup --from ftp://example.com 2>&1", 1)
    assert_match "_burner", shell_output("#{bin}/burner completions bash")
    assert_path_exists man1/"burner.1"
    assert_path_exists man1/"burner-run.1"
    assert_path_exists pkgshare/"vmlinux-aarch64"
    assert_path_exists pkgshare/"alpine-aarch64.ext4.gz"
    pin = (pkgshare/"pins").read
    assert_match(/\A\h{64}  debian-aarch64\.ext4\.gz\n\z/, pin)
    # all zeros is the placeholder until a release fills the pin in: burner
    # takes it as no pin and says so, before it fetches anything
    if pin.start_with?("0" * 64)
      assert_match "all-zero placeholder", shell_output("#{bin}/burner setup debian 2>&1", 1)
    end
  end
end
