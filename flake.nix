{
  description = "AIP service for Grain";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-analyzer-src.follows = "";
    };
  };

  outputs = { self, nixpkgs, crane, fenix }:
    let
      systems = [ "x86_64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      mkPackagesForSystem = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = { allowUnfree = true; };
          };

          # Configure crane with stable Rust toolchain
          craneLib = (crane.mkLib pkgs).overrideToolchain
            fenix.packages.${system}.stable.toolchain;

          # Project source for crane
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              (craneLib.filterCargoSources path type) ||
              (pkgs.lib.hasInfix "/templates/" path) ||
              (pkgs.lib.hasInfix "/static/" path) ||
              (pkgs.lib.hasSuffix "/templates" path) ||
              (pkgs.lib.hasSuffix "/static" path) ||
              (pkgs.lib.hasInfix "/migrations/" path) ||
              (pkgs.lib.hasSuffix "/migrations" path);
          };

          commonArgs = {
            inherit src;
            version = "0.1.0";
            strictDeps = true;
            pname = "aip";
            name = "aip";
            buildInputs = with pkgs; [
              openssl
              pkg-config
            ];
            nativeBuildInputs = with pkgs; [
              pkg-config
              openssl.dev
              # Add sqlx-cli for migrations
              sqlx-cli
            ];

            # Environment variables for OpenSSL
            OPENSSL_NO_VENDOR = 1;
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

            # Environment variables for SQLx
            SQLX_OFFLINE = "true";
          };

          sqliteArgs = commonArgs // {
            # Pass arguments to cargo build for SQLite
            cargoExtraArgs = "--no-default-features --features embed,sqlite --bin aip";
          };

          postgresArgs = commonArgs // {
            # Add PostgreSQL dependency for postgres builds
            buildInputs = commonArgs.buildInputs ++ [ pkgs.postgresql ];
            # Pass arguments to cargo build for PostgreSQL
            cargoExtraArgs = "--no-default-features --features embed,postgres --bin aip";
          };

          # Separate cargo artifacts for different builds
          sqliteCargoArtifacts = craneLib.buildDepsOnly sqliteArgs;
          postgresCargoArtifacts = craneLib.buildDepsOnly postgresArgs;

          # SQLite builds
          aip-sqlite = craneLib.buildPackage (sqliteArgs // {
            cargoArtifacts = sqliteCargoArtifacts;
            doCheck = false;
            CARGO_PROFILE = "release";
          });

          aip-client-management-sqlite = craneLib.buildPackage (sqliteArgs // {
            cargoArtifacts = sqliteCargoArtifacts;
            doCheck = false;
            CARGO_PROFILE = "release";
            cargoExtraArgs = "--no-default-features --features embed,sqlite --bin aip-client-management";
          });

          # PostgreSQL builds
          aip-postgres = craneLib.buildPackage (postgresArgs // {
            cargoArtifacts = postgresCargoArtifacts;
            doCheck = false;
            CARGO_PROFILE = "release";
          });

          aip-client-management-postgres = craneLib.buildPackage (postgresArgs // {
            cargoArtifacts = postgresCargoArtifacts;
            doCheck = false;
            CARGO_PROFILE = "release";
            cargoExtraArgs = "--no-default-features --features embed,postgres --bin aip-client-management";
          });


          # Copy migration files
          migrationFiles = pkgs.stdenv.mkDerivation {
            name = "aip-migrations";
            src = ./migrations;
            installPhase = ''
              mkdir -p $out/migrations
              cp -r * $out/migrations/
            '';
          };

          # Copy static files
          staticFiles = pkgs.stdenv.mkDerivation {
            name = "aip-static";
            src = ./static;
            installPhase = ''
              mkdir -p $out/static
              cp -r * $out/static/
            '';
          };

          # Migration runner script
          migrationRunner = pkgs.writeShellScriptBin "run-migrations" ''
            set -e

            if [ -z "$DATABASE_URL" ]; then
              echo "DATABASE_URL environment variable is required"
              exit 1
            fi

            # Determine migration source based on database type
            if [[ "$DATABASE_URL" == sqlite* ]]; then
              # Ensure /data directory exists and is writable for SQLite
              mkdir -p /data
              chmod 755 /data
              MIGRATION_SOURCE="${migrationFiles}/migrations/sqlite"
            elif [[ "$DATABASE_URL" == postgres* ]]; then
              MIGRATION_SOURCE="${migrationFiles}/migrations/postgres"
            else
              echo "Unsupported database type in DATABASE_URL: $DATABASE_URL"
              exit 1
            fi

            echo "Running migrations from $MIGRATION_SOURCE against $DATABASE_URL"
            ${pkgs.sqlx-cli}/bin/sqlx database create
            ${pkgs.sqlx-cli}/bin/sqlx migrate run --source "$MIGRATION_SOURCE"

            # Ensure the database file is writable by all users (SQLite only)
            if [[ "$DATABASE_URL" == sqlite* ]]; then
              DB_FILE=$(echo "$DATABASE_URL" | sed 's/sqlite:\/\///')
              if [ -f "$DB_FILE" ]; then
                chmod 666 "$DB_FILE"
              fi
            fi
          '';

          # Common OCI labels
          ociLabels = {
            "org.opencontainers.image.title" = "aip";
            "org.opencontainers.image.description" = "ATProtocol Identity Provider - OAuth 2.1 authorization server with ATProtocol integration";
            "org.opencontainers.image.version" = "0.1.0";
            "org.opencontainers.image.authors" = "Graze Social";
            "org.opencontainers.image.licenses" = "MIT";
          };

          # Docker images for deployment
          aipImg-sqlite = pkgs.dockerTools.buildImage {
            name = "aip";
            tag = "sqlite";
            fromImage = pkgs.dockerTools.pullImage {
              imageName = "alpine";
              imageDigest = "sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d";
              sha256 = "sha256-Sfb0quuaHgzxA7paz5P51WhdA35to39HtOufceXixz0=";
            };
            copyToRoot = pkgs.buildEnv {
              name = "image-root";
              paths = [
                aip-sqlite
                aip-client-management-sqlite
                migrationRunner
                staticFiles
                pkgs.cacert
                pkgs.sqlx-cli
                pkgs.sqlite
              ];
              pathsToLink = [ "/bin" "/etc" "/static" ];
            };

            config = {
              Cmd = [ "/bin/sh" "-c" "if [ ! -f /data/aip.db ]; then /bin/run-migrations; fi && /bin/aip" ];
              Env = [
                "RUST_BACKTRACE=1"
                "RUST_LOG=info"
                "PORT=8080"
                "HTTP_STATIC_PATH=/static"
                "STORAGE_BACKEND=sqlite"
              ];
              ExposedPorts = {
                "8080/tcp" = {};
              };
              Labels = ociLabels;
            };
          };

          aipImg-postgres = pkgs.dockerTools.buildImage {
            name = "aip";
            tag = "postgres";
            fromImage = pkgs.dockerTools.pullImage {
              imageName = "alpine";
              imageDigest = "sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d";
              sha256 = "sha256-Sfb0quuaHgzxA7paz5P51WhdA35to39HtOufceXixz0=";
            };
            copyToRoot = pkgs.buildEnv {
              name = "image-root";
              paths = [
                aip-postgres
                aip-client-management-postgres
                migrationRunner
                staticFiles
                pkgs.cacert
                pkgs.sqlx-cli
                pkgs.postgresql  # Include PostgreSQL client tools
              ];
              pathsToLink = [ "/bin" "/etc" "/static" ];
            };

            config = {
              Cmd = [ "/bin/sh" "-c" "/bin/run-migrations && /bin/aip" ];
              Env = [
                "RUST_BACKTRACE=1"
                "RUST_LOG=info"
                "PORT=8080"
                "HTTP_STATIC_PATH=/static"
                "STORAGE_BACKEND=postgres"
              ];
              ExposedPorts = {
                "8080/tcp" = {};
              };
              Labels = ociLabels;
            };
          };

        in
        {
          inherit migrationRunner;
          inherit aip-sqlite aip-client-management-sqlite aipImg-sqlite;
          inherit aip-postgres aip-client-management-postgres aipImg-postgres;
          default = aip-sqlite;
        };
    in
    {
      packages = forAllSystems mkPackagesForSystem;

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          craneLib = (crane.mkLib pkgs).overrideToolchain
            fenix.packages.${system}.stable.toolchain;
        in
        {
          default = craneLib.devShell {
            packages = with pkgs; [
              nixpkgs-fmt
              nil
              dive
              sqlite
              postgresql
              sqlx-cli
            ];

            # Set up environment for development
            RUST_LOG = "info";
          };
        });
    };
}
