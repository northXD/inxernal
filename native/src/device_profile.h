// =============================================================================
//  INXERNAL anti-ban - coherent device profile (Samsung Galaxy S24 Ultra)
// -----------------------------------------------------------------------------
//  Presents ONE consistent real device to the game's telemetry. The emulator's
//  real tells (x86 /proc/cpuinfo = "AMD Ryzen", ro.product.cpu.abi = x86_64,
//  /system/xbin/su present, Android 9) are what get an account flagged; these
//  values replace them with a Galaxy S24 Ultra (SM-S928B, Snapdragon 8 Gen 3,
//  Android 14 / SDK 34). EDIT HERE to change the impersonated device - keep every
//  field mutually consistent (model <-> fingerprint <-> cpuinfo <-> abi).
//
//  NOTE: inconsistent spoofing is worse than none. If you change the model, also
//  update the fingerprint, board/platform, cpuinfo cores, and abi together.
// =============================================================================
#pragma once

namespace nx::dev {

// ---- system properties (ro.*) ----------------------------------------------
// key -> value. Reads of these should return the spoofed value.
struct Prop { const char* key; const char* val; };

static const Prop PROPS[] = {
    { "ro.product.model",              "SM-S928B" },
    { "ro.product.name",               "e3qxeea" },
    { "ro.product.device",             "e3q" },
    { "ro.product.brand",              "samsung" },
    { "ro.product.manufacturer",       "samsung" },
    { "ro.product.board",              "pineapple" },
    { "ro.board.platform",             "pineapple" },
    { "ro.hardware",                   "qcom" },
    { "ro.arch",                       "arm64" },
    { "ro.product.cpu.abi",            "arm64-v8a" },
    { "ro.product.cpu.abilist",        "arm64-v8a,armeabi-v7a,armeabi" },
    { "ro.product.cpu.abilist64",      "arm64-v8a" },
    { "ro.product.cpu.abilist32",      "armeabi-v7a,armeabi" },
    { "ro.build.version.release",      "14" },
    { "ro.build.version.sdk",          "34" },
    { "ro.build.version.security_patch","2024-11-01" },
    { "ro.build.id",                   "UP1A.231005.007" },
    { "ro.build.display.id",           "UP1A.231005.007.S928BXXU1AWL5" },
    { "ro.build.type",                 "user" },
    { "ro.build.tags",                 "release-keys" },
    { "ro.build.flavor",               "e3qxeea-user" },
    { "ro.bootloader",                 "S928BXXU1AWL5" },
    { "ro.boot.hardware",              "qcom" },
    { "ro.kernel.qemu",                "0" },
    { "ro.build.fingerprint",
      "samsung/e3qxeea/e3q:14/UP1A.231005.007/S928BXXU1AWL5:user/release-keys" },
    { "ro.build.description",
      "e3qxeea-user 14 UP1A.231005.007 S928BXXU1AWL5 release-keys" },
};
static const int PROPS_N = sizeof(PROPS) / sizeof(PROPS[0]);

// ---- Java android.os.Build fields (for the JNI path) -----------------------
struct BuildField { const char* field; const char* val; };
static const BuildField BUILD_FIELDS[] = {
    { "MODEL",        "SM-S928B" },
    { "DEVICE",       "e3q" },
    { "PRODUCT",      "e3qxeea" },
    { "BRAND",        "samsung" },
    { "MANUFACTURER", "samsung" },
    { "BOARD",        "pineapple" },
    { "HARDWARE",     "qcom" },
    { "BOOTLOADER",   "S928BXXU1AWL5" },
    { "FINGERPRINT",
      "samsung/e3qxeea/e3q:14/UP1A.231005.007/S928BXXU1AWL5:user/release-keys" },
    { "TAGS",         "release-keys" },
    { "TYPE",         "user" },
};
static const int BUILD_FIELDS_N = sizeof(BUILD_FIELDS) / sizeof(BUILD_FIELDS[0]);
// Build.VERSION.RELEASE = "14", Build.VERSION.SDK_INT = 34 (handled separately).

// ---- /proc/cpuinfo (Snapdragon 8 Gen 3 / SM8650, 8 cores: 1xX4 3xA720 2xA720
//      2xA520). Implementer 0x41 (ARM). Parts: X4=0xd82, A720=0xd81, A520=0xd80.
static const char* CPUINFO =
"processor\t: 0\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x1\n"
"CPU part\t: 0xd80\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 1\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x1\n"
"CPU part\t: 0xd80\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 2\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x0\n"
"CPU part\t: 0xd81\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 3\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x0\n"
"CPU part\t: 0xd81\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 4\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x0\n"
"CPU part\t: 0xd81\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 5\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x0\n"
"CPU part\t: 0xd81\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 6\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x0\n"
"CPU part\t: 0xd81\n"
"CPU revision\t: 0\n"
"\n"
"processor\t: 7\n"
"BogoMIPS\t: 38.40\n"
"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte ecv\n"
"CPU implementer\t: 0x41\n"
"CPU architecture: 8\n"
"CPU variant\t: 0x1\n"
"CPU part\t: 0xd82\n"
"CPU revision\t: 0\n"
"\n"
"Hardware\t: Qualcomm Technologies, Inc SM8650\n";

// ---- paths that must appear ABSENT (root / emulator markers) -----------------
static const char* HIDE_PATHS[] = {
    "/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
    "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
    "/system/xbin/busybox", "/system/bin/busybox",
    "/system/app/Superuser.apk", "/system/xbin/daemonsu",
    "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/qemu_trace",
};
static const int HIDE_PATHS_N = sizeof(HIDE_PATHS) / sizeof(HIDE_PATHS[0]);

// paths whose CONTENT we replace (open -> our spoofed file)
static const char* CPUINFO_PATH = "/proc/cpuinfo";

} // namespace nx::dev
