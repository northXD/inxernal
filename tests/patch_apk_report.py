"""Disable only Promon's final Android crash-dispatch call in an APK.

The reporter method itself is intentionally left running: only the final
``Thread.UncaughtExceptionHandler.uncaughtException(Thread, Throwable)``
invoke in ``pkbpqnzc.aG.a(String)`` is replaced by three NOP code units.  The
DEX signature/checksum and ZIP CRC fields are then repaired without repacking
the APK, so every entry offset and every unrelated byte stays put.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import shutil
import struct
import zipfile
import zlib
from pathlib import Path


TARGET_DEX = "classes2.dex"
TARGET_CLASS = "Lpkbpqnzc/aG;"
TARGET_NAME = "a"
TARGET_RETURN = "V"
TARGET_PARAMS = ("Ljava/lang/String;",)
HANDLER_CLASS = "Ljava/lang/Thread$UncaughtExceptionHandler;"
HANDLER_NAME = "uncaughtException"
HANDLER_RETURN = "V"
HANDLER_PARAMS = ("Ljava/lang/Thread;", "Ljava/lang/Throwable;")

# This patch is deliberately version-locked.  Silently applying an offset or
# pattern to another Hay Day build would be much riskier than refusing it.
EXPECTED_APK_SHA256 = "65faf52b55217beb6a23b9bc122e420e2df3407cd482b3379427878d345dc49c"
EXPECTED_DEX_SHA256 = "eb724b7d2091972b947de812852b093bf26114c075ee6518bc1457ca03219a01"
EXPECTED_PATCHED_APK_SHA256 = "4870fb4e6ad73335deeaba70dc38db81b4c97e80fba324e50a010eccee66f1a5"


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_uleb128(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("invalid ULEB128")


class Dex:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        if not self.data.startswith(b"dex\n"):
            raise ValueError("not a DEX file")

        self.string_ids_size, self.string_ids_off = u32(self.data, 56), u32(self.data, 60)
        self.type_ids_size, self.type_ids_off = u32(self.data, 64), u32(self.data, 68)
        self.proto_ids_size, self.proto_ids_off = u32(self.data, 72), u32(self.data, 76)
        self.method_ids_size, self.method_ids_off = u32(self.data, 88), u32(self.data, 92)
        self.class_defs_size, self.class_defs_off = u32(self.data, 96), u32(self.data, 100)
        self._strings: dict[int, str] = {}

    def string(self, index: int) -> str:
        if index not in self._strings:
            if not 0 <= index < self.string_ids_size:
                raise IndexError(index)
            offset = u32(self.data, self.string_ids_off + index * 4)
            _, offset = read_uleb128(self.data, offset)
            end = self.data.index(0, offset)
            self._strings[index] = bytes(self.data[offset:end]).decode("utf-8")
        return self._strings[index]

    def type_descriptor(self, index: int) -> str:
        if not 0 <= index < self.type_ids_size:
            raise IndexError(index)
        string_index = u32(self.data, self.type_ids_off + index * 4)
        return self.string(string_index)

    def proto(self, index: int) -> tuple[str, tuple[str, ...]]:
        if not 0 <= index < self.proto_ids_size:
            raise IndexError(index)
        offset = self.proto_ids_off + index * 12
        return_type = self.type_descriptor(u32(self.data, offset + 4))
        parameters_off = u32(self.data, offset + 8)
        params: list[str] = []
        if parameters_off:
            size = u32(self.data, parameters_off)
            for item in range(size):
                params.append(self.type_descriptor(u16(self.data, parameters_off + 4 + item * 2)))
        return return_type, tuple(params)

    def find_target_method_index(self) -> tuple[int, int]:
        class_type_index = -1
        for index in range(self.type_ids_size):
            if self.type_descriptor(index) == TARGET_CLASS:
                class_type_index = index
                break
        if class_type_index < 0:
            raise ValueError(f"class not found: {TARGET_CLASS}")

        for index in range(self.method_ids_size):
            offset = self.method_ids_off + index * 8
            class_index = u16(self.data, offset)
            proto_index = u16(self.data, offset + 2)
            name_index = u32(self.data, offset + 4)
            if class_index != class_type_index or self.string(name_index) != TARGET_NAME:
                continue
            return_type, params = self.proto(proto_index)
            if return_type == TARGET_RETURN and params == TARGET_PARAMS:
                return index, class_type_index
        raise ValueError("target method signature not found")

    def find_code_offset(self, method_index: int, class_type_index: int) -> int:
        class_data_off = 0
        for index in range(self.class_defs_size):
            offset = self.class_defs_off + index * 32
            if u32(self.data, offset) == class_type_index:
                class_data_off = u32(self.data, offset + 24)
                break
        if class_data_off == 0:
            raise ValueError("target class data not found")

        cursor = class_data_off
        sizes = []
        for _ in range(4):
            value, cursor = read_uleb128(self.data, cursor)
            sizes.append(value)
        static_fields, instance_fields, direct_methods, virtual_methods = sizes

        for _ in range(static_fields + instance_fields):
            _, cursor = read_uleb128(self.data, cursor)
            _, cursor = read_uleb128(self.data, cursor)

        for method_count in (direct_methods, virtual_methods):
            current_method = 0
            for _ in range(method_count):
                diff, cursor = read_uleb128(self.data, cursor)
                current_method += diff
                _, cursor = read_uleb128(self.data, cursor)
                code_off, cursor = read_uleb128(self.data, cursor)
                if current_method == method_index:
                    if code_off == 0:
                        raise ValueError("target method has no code")
                    return code_off
        raise ValueError("target encoded method not found")

    def find_handler_method_index(self) -> int:
        for index in range(self.method_ids_size):
            offset = self.method_ids_off + index * 8
            class_index = u16(self.data, offset)
            proto_index = u16(self.data, offset + 2)
            name_index = u32(self.data, offset + 4)
            if self.type_descriptor(class_index) != HANDLER_CLASS:
                continue
            if self.string(name_index) != HANDLER_NAME:
                continue
            return_type, params = self.proto(proto_index)
            if return_type == HANDLER_RETURN and params == HANDLER_PARAMS:
                return index
        raise ValueError("uncaught-exception handler method reference not found")

    def patch(self) -> tuple[bytes, int, tuple[int, int, int]]:
        method_index, class_type_index = self.find_target_method_index()
        code_off = self.find_code_offset(method_index, class_type_index)
        insns_size = u32(self.data, code_off + 12)
        if insns_size < 3:
            raise ValueError("empty target method")
        instruction_start = code_off + 16
        handler_index = self.find_handler_method_index()
        matches: list[int] = []
        for unit in range(insns_size - 2):
            candidate = instruction_start + unit * 2
            first = u16(self.data, candidate)
            # invoke-interface is format 35c and occupies three code units.
            if first & 0xFF == 0x72 and u16(self.data, candidate + 2) == handler_index:
                matches.append(candidate)
        if len(matches) != 1:
            raise ValueError(f"expected exactly one handler invoke, found {len(matches)}")

        instruction_off = matches[0]
        original = tuple(u16(self.data, instruction_off + index * 2) for index in range(3))
        if original != (0x3072, handler_index, 0x0210):
            raise ValueError(
                "unexpected handler invoke: " +
                " ".join(f"{item:#06x}" for item in original)
            )

        # Keep the reporter/control flow intact and remove only its deliberate
        # dispatch into RuntimeInit.KillApplicationHandler.
        struct.pack_into("<HHH", self.data, instruction_off, 0x0000, 0x0000, 0x0000)
        self.data[12:32] = hashlib.sha1(self.data[32:]).digest()
        struct.pack_into("<I", self.data, 8, zlib.adler32(self.data[12:]) & 0xFFFFFFFF)
        return bytes(self.data), instruction_off, original


def find_zip_offsets(apk: bytes | bytearray, entry_name: str) -> tuple[int, int]:
    eocd = apk.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("ZIP EOCD not found")
    entries = u16(apk, eocd + 10)
    cursor = u32(apk, eocd + 16)

    for _ in range(entries):
        if apk[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError(f"invalid central directory at {cursor:#x}")
        name_len = u16(apk, cursor + 28)
        extra_len = u16(apk, cursor + 30)
        comment_len = u16(apk, cursor + 32)
        name = bytes(apk[cursor + 46:cursor + 46 + name_len]).decode("utf-8")
        if name == entry_name:
            local = u32(apk, cursor + 42)
            if apk[local:local + 4] != b"PK\x03\x04":
                raise ValueError("invalid local header")
            local_name_len = u16(apk, local + 26)
            local_extra_len = u16(apk, local + 28)
            data_off = local + 30 + local_name_len + local_extra_len
            return data_off, cursor
        cursor += 46 + name_len + extra_len + comment_len
    raise ValueError(f"ZIP entry not found: {entry_name}")


def patch_apk(source: Path, output: Path) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("output must differ from source")
    source_bytes = source.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if source_hash != EXPECTED_APK_SHA256:
        raise ValueError(
            f"unsupported source APK SHA256: {source_hash}; "
            f"expected {EXPECTED_APK_SHA256}"
        )
    shutil.copy2(source, output)
    apk = bytearray(source_bytes)

    with zipfile.ZipFile(source) as archive:
        info = archive.getinfo(TARGET_DEX)
        if info.compress_type != zipfile.ZIP_STORED:
            raise ValueError(f"{TARGET_DEX} must be stored, not compressed")
        original_dex = archive.read(info)
    dex_hash = hashlib.sha256(original_dex).hexdigest()
    if dex_hash != EXPECTED_DEX_SHA256:
        raise ValueError(
            f"unsupported {TARGET_DEX} SHA256: {dex_hash}; "
            f"expected {EXPECTED_DEX_SHA256}"
        )

    patched_dex, dex_instruction_off, original_instruction = Dex(original_dex).patch()
    if len(patched_dex) != len(original_dex):
        raise RuntimeError("DEX size changed")

    apk_data_off, central_off = find_zip_offsets(apk, TARGET_DEX)
    if bytes(apk[apk_data_off:apk_data_off + len(original_dex)]) != original_dex:
        raise RuntimeError("local ZIP data does not match extracted DEX")
    apk[apk_data_off:apk_data_off + len(patched_dex)] = patched_dex

    crc = binascii.crc32(patched_dex) & 0xFFFFFFFF
    local_header = apk_data_off - (30 + u16(apk, central_off + 28) + 0)
    # Use the authoritative local-header offset from the central record because
    # the local extra-field length is not necessarily the central one.
    local_header = u32(apk, central_off + 42)
    struct.pack_into("<I", apk, local_header + 14, crc)
    struct.pack_into("<I", apk, central_off + 16, crc)
    output.write_bytes(apk)

    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("patched APK failed ZIP CRC verification")
        verified = archive.read(TARGET_DEX)
    if verified != patched_dex:
        raise RuntimeError("patched DEX verification failed")

    print(f"method index patched at DEX offset {dex_instruction_off:#x}")
    print(
        "original code units: " +
        " ".join(f"{item:#06x}" for item in original_instruction) +
        "; new: 0x0000 0x0000 0x0000"
    )
    print(f"DEX CRC32: {crc:08x}")
    patched_hash = hashlib.sha256(apk).hexdigest()
    if patched_hash != EXPECTED_PATCHED_APK_SHA256:
        raise RuntimeError(
            f"unexpected patched APK SHA256: {patched_hash}; "
            f"expected {EXPECTED_PATCHED_APK_SHA256}"
        )
    print(f"APK SHA256: {patched_hash}")
    print(f"wrote {output} ({len(apk):,} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    patch_apk(args.source, args.output)


if __name__ == "__main__":
    main()
