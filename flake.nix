{
	description = "FUTO's MDNS library";

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
	};

	outputs = {
		self,
		nixpkgs,
	}: let
		system = "x86_64-linux";
		pkgs = nixpkgs.legacyPackages.${system};

		sourceRepo =
			pkgs.fetchFromGitHub {
				owner = "futo-org";
				repo = "FUTO.MDNS";
				rev = "3c7ccbd2df32d454d7b06a0933d1944e9fbc48fa";
				hash = "sha256-bgTac8IiJY6DZWLJWIK7k5kcf8XVtz8+8cipDYIg2hA=";
			};
	in {
		packages.${system}.default = let
		in
			pkgs.buildDotnetModule {
				name = "futo-mdns";

				src = "${sourceRepo}/FUTO.MDNS";
				dotnetInstallPath = "$out/lib";

				meta = {
					description = "FUTO's MDNS library";
				};
			};
	};
}
