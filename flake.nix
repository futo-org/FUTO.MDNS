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

		getArch = system: nix2Net."${system}";
		nix2Net = {
			x86_64-linux = "linux-x64";
		};

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
				pubDir = "./bin/Release/net8.0/${getArch system}/publish";

				meta = {
					description = "FUTO's MDNS library";
				};
			};
	};
}
