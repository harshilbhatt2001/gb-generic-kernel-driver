{ lib
, stdenv
, kmod
, pkgs
}:
let
  kernelPkg = pkgs.linuxPackages_6_11.kernel;
in
stdenv.mkDerivation rec {
  pname = "gb-esp32";
  version = "0.1.0";
  src = ./.;
  nativeBuildInputs = kernelPkg.moduleBuildDependencies;
  buildInputs = [ kmod ] ++ kernelPkg.moduleBuildDependencies;
  makeFlags = [
    "KERNELRELEASE=${kernelPkg.modDirVersion}"
    "KERNELDIR=${kernelPkg.dev}/lib/modules/${kernelPkg.modDirVersion}/build"
    "INSTALL_MOD_PATH=$(out)"
  ];
  NIX_CFLAGS_COMPILE = [
    "-Wno-error=incompatible-pointer-types"
    "-Wno-error=discarded-qualifiers"
  ];
  #patchPhase = ''
  #  sed -i 's/class_create(THIS_MODULE, CLASS_NAME)/class_create(CLASS_NAME)/' netlink.c
  #'';
  buildPhase = ''
    make -C ${kernelPkg.dev}/lib/modules/${kernelPkg.modDirVersion}/build \
      M=$(pwd) \
      modules
  '';
  installPhase = ''
    mkdir -p $out/lib/modules/${kernelPkg.modDirVersion}/extra
    cp *.ko $out/lib/modules/${kernelPkg.modDirVersion}/extra/
    
    # Copy necessary files from the kernel
    mkdir -p $out/lib/modules/${kernelPkg.modDirVersion}
    cp ${kernelPkg}/lib/modules/${kernelPkg.modDirVersion}/modules.order \
       ${kernelPkg}/lib/modules/${kernelPkg.modDirVersion}/modules.builtin \
       ${kernelPkg}/lib/modules/${kernelPkg.modDirVersion}/modules.builtin.modinfo \
       $out/lib/modules/${kernelPkg.modDirVersion}/
    
    # Run depmod
    ${pkgs.kmod}/bin/depmod -b $out ${kernelPkg.modDirVersion}
  '';
  meta = with lib; {
    description = "";
    license = licenses.gpl2;
    platforms = platforms.linux;
    maintainers = with maintainers; [ "Harshil Bhatt <harshilbhatt2001@gmail.com>" ];
  };
}
