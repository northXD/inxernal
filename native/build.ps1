# Build the INXERNAL native engine (aarch64 shared library) with the Android NDK.
# Output: native/build/libnxrth.so  (arm64-v8a, loaded into the game under Houdini)
$ErrorActionPreference = "Stop"
$ndk = "C:\Program Files (x86)\Android\AndroidNDK\android-ndk-r27c"
$cxx = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang++.cmd"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out  = Join-Path $here "build"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$srcs = @(
    (Join-Path $here "src\main.cpp")
)
$soPath = Join-Path $out "libnxrth.so"

# -static-libstdc++ folds the C++ runtime in, so the module only NEEDs system
# libs (liblog/libm/libdl/libc) that are always present -> the bootstrap dlopen
# cannot fail on a missing libc++_shared.so.
$args = @(
    "-shared", "-fPIC", "-O2", "-std=c++17",
    "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections",
    "-static-libstdc++",
    "-Wl,--gc-sections", "-Wl,-z,max-page-size=16384", "-Wl,--exclude-libs,ALL",
    "-I", (Join-Path $here "src"),
    "-o", $soPath
) + $srcs + @("-llog")

Write-Host "[build] $cxx" -ForegroundColor Cyan
& $cxx @args
if ($LASTEXITCODE -ne 0) { throw "compile failed ($LASTEXITCODE)" }
Write-Host "[build] OK -> $soPath" -ForegroundColor Green
Get-Item $soPath | Select-Object Length, LastWriteTime
