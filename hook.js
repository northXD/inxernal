"use strict";

// Hay Day 1.72.2 on LDPlayer 9 runs the ARM64 game image through Houdini.
// Frida's host ModuleMap only describes x86-64 modules, so libg.so must be
// treated as a guest mapping instead of using Process.findModuleByName().
var TARGET_LIB = "libg.so";
var TARGET_GUEST_ARCH = "arm64";
var TARGET_GUEST_BASE = ptr("0x05040000");
var TARGET_FILE_SIZE = 23415808;
var ELF_MAGIC = 0x464c457f;
var MAX_TRANSFER = 16 * 1024 * 1024;
var MAX_SCAN_RESULTS = 4096;
var TARGET_SCAN_SEGMENTS = [
    { offset: 0x0000000, size: 0x141f000 },
    { offset: 0x1422000, size: 0x0e5000 },
    { offset: 0x150a000, size: 0x0ad000 },
    { offset: 0x15fc000, size: 0x055000 },
    { offset: 0x1651000, size: 0x003c00 }
];

var target = {
    base: null,
    size: 0,
    path: null,
    readySince: null
};
var targetWatcher = null;
var initialized = false;

// Code caves must be kept referenced or Frida frees the allocation.
var codeCaves = [];

var spawnResume = {
    listenerInstalled: false,
    complete: false,
    detail: null,
    listener: null
};

function emit(text) {
    send(text);
}

function installSpawnResumeBarrier() {
    try {
        var libc = Process.getModuleByName("libc.so");
        var raiseAddress = libc.getExportByName("raise");
        spawnResume.listener = Interceptor.attach(raiseAddress, {
            onEnter: function (args) {
                this.isSpawnStop =
                    Process.getCurrentThreadId() === Process.id &&
                    args[0].toInt32() === 19;
            },
            onLeave: function () {
                if (!this.isSpawnStop || spawnResume.complete) return;
                spawnResume.complete = true;
                spawnResume.detail = "Frida spawn rollback completed";
                emit("[SPAWN] Resume handshake completed");
                setImmediate(function () {
                    try {
                        if (spawnResume.listener !== null)
                            spawnResume.listener.detach();
                    } catch (_) {}
                    spawnResume.listener = null;
                });
            }
        });
        spawnResume.listenerInstalled = true;
    } catch (error) {
        spawnResume.detail = String(error);
        emit("[SPAWN] Could not install resume barrier: " + error);
    }
}

function hasElfMagic(address) {
    try {
        return address.readU32() === ELF_MAGIC;
    } catch (_) {
        return false;
    }
}

function resolveTarget() {
    if (target.base !== null && hasElfMagic(target.base)) return true;

    if (hasElfMagic(TARGET_GUEST_BASE)) {
        target.base = TARGET_GUEST_BASE;
        target.size = TARGET_FILE_SIZE;
        target.path = "guest:" + TARGET_LIB;
        target.readySince = Date.now();
        emit("[ENGINE] " + TARGET_LIB + " guest base " + target.base);
        return true;
    }

    return false;
}

function startTargetWatcher() {
    if (targetWatcher !== null || target.base !== null) return;
    targetWatcher = setInterval(function () {
        if (resolveTarget()) {
            clearInterval(targetWatcher);
            targetWatcher = null;
        }
    }, 250);
}

function requireTarget() {
    if (!resolveTarget()) throw new Error(TARGET_LIB + " is not loaded");
    return target.base;
}

function parseInteger(value, label) {
    var number = typeof value === "number" ? value : Number(String(value));
    if (!Number.isFinite(number) || !Number.isSafeInteger(number))
        throw new Error(label + " must be a safe integer");
    return number;
}

function parseOffset(value) {
    var offset = parseInteger(value, "offset");
    if (offset < 0 || offset >= TARGET_FILE_SIZE)
        throw new Error("offset is outside " + TARGET_LIB);
    return offset;
}

function parseLength(value) {
    var length = parseInteger(value, "length");
    if (length <= 0 || length > MAX_TRANSFER)
        throw new Error("length must be between 1 and " + MAX_TRANSFER);
    return length;
}

function addressAt(offset, length) {
    var parsedOffset = parseOffset(offset);
    var parsedLength = length === undefined ? 1 : parseLength(length);
    if (parsedOffset + parsedLength > TARGET_FILE_SIZE)
        throw new Error("requested range exceeds " + TARGET_LIB);
    return requireTarget().add(parsedOffset);
}

function withWritable(address, length, operation) {
    var range = Process.findRangeByAddress(address);
    if (range === null) throw new Error("address is not mapped");
    if (address.add(length).compare(range.base.add(range.size)) > 0)
        throw new Error("write crosses a mapping boundary");

    var oldProtection = range.protection;
    var changed = oldProtection.charAt(1) !== "w";
    var writableProtection =
        oldProtection.charAt(0) + "w" + oldProtection.charAt(2);
    if (changed && !Memory.protect(address, length, writableProtection))
        throw new Error("could not make target memory writable");
    try {
        operation();
    } finally {
        if (changed && !Memory.protect(address, length, oldProtection))
            throw new Error("could not restore memory protection");
    }
    return true;
}

function parseHexBytes(text) {
    var normalized = String(text).replace(/\s+/g, "");
    if (normalized.length === 0 || normalized.length % 2 !== 0 ||
        !/^[0-9a-fA-F]+$/.test(normalized))
        throw new Error("bytes must be an even-length hexadecimal string");
    var bytes = [];
    for (var i = 0; i < normalized.length; i += 2)
        bytes.push(parseInt(normalized.slice(i, i + 2), 16));
    return bytes;
}

function targetFileRanges() {
    var base = requireTarget();
    var result = [];
    for (var i = 0; i < TARGET_SCAN_SEGMENTS.length; i++) {
        var segment = TARGET_SCAN_SEGMENTS[i];
        var address = base.add(segment.offset);
        var mapping = Process.findRangeByAddress(address);
        if (mapping === null ||
            address.add(segment.size).compare(mapping.base.add(mapping.size)) > 0)
            throw new Error("unexpected " + TARGET_LIB + " mapping layout");
        result.push({ base: address, size: segment.size });
    }
    return result;
}

var engine = {
    readInt: function (offset) {
        return addressAt(offset, 4).readS32();
    },
    readFloat: function (offset) {
        return addressAt(offset, 4).readFloat();
    },
    readDouble: function (offset) {
        return addressAt(offset, 8).readDouble();
    },
    readLong: function (offset) {
        return addressAt(offset, 8).readS64().toString();
    },
    readPointer: function (offset) {
        return addressAt(offset, Process.pointerSize).readPointer().toString();
    },
    readString: function (offset, length) {
        return addressAt(offset, length).readUtf8String(length);
    },
    readBytes: function (offset, length) {
        return addressAt(offset, length).readByteArray(length);
    },
    writeInt: function (offset, value) {
        var address = addressAt(offset, 4);
        return withWritable(address, 4, function () {
            address.writeS32(parseInteger(value, "value"));
        });
    },
    writeFloat: function (offset, value) {
        var address = addressAt(offset, 4);
        var parsed = Number(value);
        if (!Number.isFinite(parsed)) throw new Error("value must be finite");
        return withWritable(address, 4, function () {
            address.writeFloat(parsed);
        });
    },
    writeDouble: function (offset, value) {
        var address = addressAt(offset, 8);
        var parsed = Number(value);
        if (!Number.isFinite(parsed)) throw new Error("value must be finite");
        return withWritable(address, 8, function () {
            address.writeDouble(parsed);
        });
    },
    writeLong: function (offset, value) {
        var address = addressAt(offset, 8);
        var parsed = int64(String(value));
        return withWritable(address, 8, function () {
            address.writeS64(parsed);
        });
    },
    writeBytes: function (offset, text) {
        var bytes = parseHexBytes(text);
        var address = addressAt(offset, bytes.length);
        return withWritable(address, bytes.length, function () {
            address.writeByteArray(bytes);
        });
    },
    nop: function (offset, count) {
        var length = parseLength(count);
        if (length % 4 !== 0)
            throw new Error("ARM64 NOP length must be divisible by 4");
        var address = addressAt(offset, length);
        return withWritable(address, length, function () {
            for (var i = 0; i < length; i += 4)
                address.add(i).writeU32(0xd503201f);
        });
    },
    scan: function (pattern) {
        var matches = [];
        var ranges = targetFileRanges();
        if (ranges.length === 0)
            throw new Error("no file-backed " + TARGET_LIB + " ranges found");
        for (var i = 0; i < ranges.length && matches.length < MAX_SCAN_RESULTS; i++) {
            var found = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
            for (var j = 0; j < found.length && matches.length < MAX_SCAN_RESULTS; j++) {
                matches.push({
                    address: found[j].address.toString(),
                    offset: found[j].address.sub(target.base).toString(),
                    size: found[j].size
                });
            }
        }
        return matches;
    }
};

function info() {
    resolveTarget();
    return {
        pid: Process.id,
        arch: Process.arch,
        guestArch: TARGET_GUEST_ARCH,
        platform: Process.platform,
        houdini: Process.arch === "x64",
        base: target.base === null ? null : target.base.toString(),
        size: target.size,
        path: target.path,
        resumeComplete: spawnResume.complete,
        resumeBarrierInstalled: spawnResume.listenerInstalled,
        resumeDetail: spawnResume.detail
    };
}

installSpawnResumeBarrier();
emit("[AGENT] Ready | PID=" + Process.id + " Arch=" + Process.arch);

rpc.exports = {
    ping: function () { return "pong"; },
    status: function () {
        return {
            pid: Process.id,
            resumeComplete: spawnResume.complete,
            resumeBarrierInstalled: spawnResume.listenerInstalled,
            resumeDetail: spawnResume.detail
        };
    },
    init: function () {
        if (!initialized) {
            initialized = true;
            emit("[INIT] Watching for " + TARGET_LIB);
            if (!resolveTarget()) startTargetWatcher();
        }
        return true;
    },
    info: info,
    layout: function () {
        resolveTarget();
        return {
            base: target.base === null ? null : target.base.toString(),
            size: TARGET_FILE_SIZE,
            segments: TARGET_SCAN_SEGMENTS
        };
    },
    getbase: function () {
        resolveTarget();
        return target.base === null ? null : target.base.toString();
    },
    readint: function (offset) { return engine.readInt(offset); },
    readfloat: function (offset) { return engine.readFloat(offset); },
    readdouble: function (offset) { return engine.readDouble(offset); },
    readlong: function (offset) { return engine.readLong(offset); },
    readpointer: function (offset) { return engine.readPointer(offset); },
    readstring: function (offset, length) {
        return engine.readString(offset, parseLength(length || 256));
    },
    readbytes: function (offset, length) {
        return engine.readBytes(offset, parseLength(length));
    },
    writeint: function (offset, value) { return engine.writeInt(offset, value); },
    writefloat: function (offset, value) { return engine.writeFloat(offset, value); },
    writedouble: function (offset, value) { return engine.writeDouble(offset, value); },
    writelong: function (offset, value) { return engine.writeLong(offset, value); },
    writebytes: function (offset, text) { return engine.writeBytes(offset, text); },
    nop: function (offset, count) { return engine.nop(offset, count); },
    scan: function (pattern) { return engine.scan(String(pattern)); },
    dump: function (offset, length) {
        return engine.readBytes(offset, parseLength(length));
    },
    call: function () {
        throw new Error("native calls into Houdini guest ARM64 code are unsupported");
    },
    hookfn: function () {
        throw new Error("Interceptor cannot hook Houdini guest ARM64 addresses");
    },
    getexport: function () { return null; },
    detachhooks: function () {
        if (spawnResume.listener !== null) {
            try { spawnResume.listener.detach(); } catch (_) {}
            spawnResume.listener = null;
        }
        return true;
    },
    reattachhooks: function () { return false; },
    diagmodules: function () {
        return Process.enumerateModules().map(function (module) {
            return module.name + " | " + module.base + " | " +
                module.size + " | " + module.path;
        });
    },
    diagthreads: function () {
        return Process.enumerateThreads().map(function (thread) {
            return "tid=" + thread.id + " state=" + thread.state;
        });
    },
    scanmem: function (pattern) {
        var ranges = Process.enumerateRanges("rw-");
        var matches = [];
        for (var i = 0; i < ranges.length && matches.length < MAX_SCAN_RESULTS; i++) {
            try {
                var found = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
                for (var j = 0; j < found.length && matches.length < MAX_SCAN_RESULTS; j++) {
                    matches.push(found[j].address.toString());
                }
            } catch (e) {}
        }
        return matches;
    },
    narrowmem: function (addresses, pattern) {
        var parts = pattern.trim().split(/\s+/);
        var len = parts.length;
        var expected = [];
        for (var k = 0; k < len; k++) expected.push(parseInt(parts[k], 16));
        var surviving = [];
        for (var i = 0; i < addresses.length; i++) {
            try {
                var buf = ptr(addresses[i]).readByteArray(len);
                if (buf === null) continue;
                var view = new Uint8Array(buf);
                var ok = true;
                for (var j = 0; j < len; j++) {
                    if (view[j] !== expected[j]) { ok = false; break; }
                }
                if (ok) surviving.push(addresses[i]);
            } catch (e) {}
        }
        return surviving;
    },
    readabs: function (addr, size) {
        try {
            var buf = ptr(addr).readByteArray(size);
            if (buf === null) return null;
            return Array.prototype.slice.call(new Uint8Array(buf));
        } catch (e) { return null; }
    },
    writeabs: function (addr, byteValues) {
        try {
            var p = ptr(addr);
            var range = Process.findRangeByAddress(p);
            // range === null for Frida-owned cave allocations (already rwx);
            // in that case just write directly. For game memory, add 'w' first.
            if (range !== null && range.protection.indexOf("w") === -1) {
                Memory.protect(p, byteValues.length,
                    range.protection.charAt(0) + "w" + range.protection.charAt(2));
            }
            p.writeByteArray(byteValues);
            return true;
        } catch (e) {
            try {
                Memory.protect(ptr(addr), byteValues.length, "rwx");
                ptr(addr).writeByteArray(byteValues);
                return true;
            } catch (e2) { return false; }
        }
    },

    // Allocate executable guest memory for hand-written ARM64 shellcode.
    // Returns the absolute address; the allocation is kept alive in codeCaves.
    alloccave: function (size) {
        var n = parseInteger(size, "size");
        if (n < 16 || n > 0x100000)
            throw new Error("cave size must be between 16 and 1048576 bytes");
        var mem = Memory.alloc(n);
        Memory.protect(mem, n, "rwx");
        codeCaves.push({ mem: mem, size: n });
        emit("[CAVE] allocated " + n + " bytes at " + mem);
        return mem.toString();
    },

    // Redirect a libg.so offset to an absolute target using a 16-byte,
    // position-independent far branch (works at any distance, unlike B/BL
    // which are limited to +-128MB):
    //     LDR X17, #8   ; 58 00 00 51
    //     BR  X17       ; d6 1f 02 20
    //     .quad target  ; 8 bytes little-endian
    // Returns the 16 original bytes so the caller can build a trampoline.
    farjump: function (offset, targetAddr) {
        var src = addressAt(offset, 16);
        var target = ptr(targetAddr);
        var original = Array.prototype.slice.call(
            new Uint8Array(src.readByteArray(16))
        );
        var stub = [0x51, 0x00, 0x00, 0x58, 0x20, 0x02, 0x1f, 0xd6];
        // Encode the 64-bit target little-endian.
        var t = uint64(target.toString());
        for (var i = 0; i < 8; i++) {
            stub.push(t.shr(i * 8).and(0xff).toNumber());
        }
        withWritable(src, 16, function () {
            src.writeByteArray(stub);
        });
        emit("[FARJUMP] " + src + " -> " + target);
        return original;
    },

    // Build the 4 bytes of an ARM64 B or BL instruction jumping from a
    // libg.so offset to an absolute target (must be within +-128MB).
    // Does not write anything; returns the encoded bytes for writeabs/writebytes.
    makebranch: function (offset, targetAddr, link) {
        var src = requireTarget().add(parseOffset(offset));
        var target = ptr(targetAddr);
        var delta = target.sub(src);
        var imm = delta.toInt32() >> 2;
        if (imm < -(1 << 25) || imm >= (1 << 25))
            throw new Error("branch target out of +-128MB range; use farjump");
        var op = (link ? 0x94000000 : 0x14000000) | (imm & 0x03ffffff);
        return [op & 0xff, (op >> 8) & 0xff, (op >> 16) & 0xff, (op >> 24) & 0xff];
    }
};
