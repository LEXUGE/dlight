{
  description = "A DNS tunnel proxy tool using KCP";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, utils, ... }:
    utils.lib.eachSystem (utils.lib.defaultSystems) (system: rec {

      apps = {
        gencert = utils.lib.mkApp {
          drv = with import nixpkgs { system = "${system}"; };
            pkgs.writeShellScriptBin "dcompass-update-data" ''
              set -ex
              cd data/
              openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca.key -out rootca.crt
              openssl req -new -batch -nodes -sha256 -keyout cert.key -out cert.csr -subj '/C=GB/CN=dlight.tech'
              openssl x509 -req -days 10000 -in cert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out cert.crt
              openssl verify -CAfile rootca.crt cert.crt
              cp cert.crt cert-big.crt
              cat cert.crt >> cert-big.crt
              cat cert.crt >> cert-big.crt
              cat cert.crt >> cert-big.crt
              cat cert.crt >> cert-big.crt
              rm cert.csr
              rm rootca.key
              rm rootca.srl
            '';
        };
      };

      # `nix develop`
      devShell = with import nixpkgs {
        system = "${system}";
        overlays = [ rust-overlay.overlay ];
      };
        mkShell {
          nativeBuildInputs = [
            # write rustfmt first to ensure we are using nightly rustfmt
            rust-bin.nightly."2021-01-01".rustfmt
            (rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            })
            rust-analyzer

            # required by BoringSSL in quiche
            cmake
            # required to generate certs
            openssl

            binutils-unwrapped
            cargo-cache
          ];
        };
    });
}
