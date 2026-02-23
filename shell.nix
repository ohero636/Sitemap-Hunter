{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    (pkgs.python3.withPackages (ps: with ps; [
      requests
      aiohttp
      beautifulsoup4
    ]))
  ];

  shellHook = ''
    echo "NeroHunt environment active. Run: python sitemap_hunter.py <url>"
  '';
}
