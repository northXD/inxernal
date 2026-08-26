'use strict';

// Read-only startup telemetry for the Code16/JNI_OnLoad path.
//
// Load this as a second Frida script before resuming the spawned app.  It does
// not clear, replace, or suppress any exception.  On ExceptionCheck entry it
// uses only ExceptionOccurred + DeleteLocalRef, both of which are permitted
// while an exception is pending, so it can still see a true condition even if
// another script changes the eventual ExceptionCheck return value in onLeave.

var TRACE_WINDOW_MS = 6000;
var MAX_EVENTS = 192;
var startedAt = Date.now();
var eventCount = 0;
var listeners = [];
var hookedAddresses = {};
var classNames = {};
var methodNames = {};
var stringValues = {};
var lastByThread = {};
var probeDepth = {};

function elapsed() {
    return Date.now() - startedAt;
}

function safeCString(address) {
    try {
        if (address === null || address.isNull()) return null;
        return address.readCString();
    } catch (_) {
        return null;
    }
}

function describe(address) {
    if (address === null || address === undefined) return null;
    try {
        var module = Process.findModuleByAddress(address);
        if (module === null) {
            return { address: address.toString(), module: null, offset: null };
        }
        return {
            address: address.toString(),
            module: module.name,
            path: module.path,
            offset: address.sub(module.base).toString()
        };
    } catch (_) {
        return { address: String(address), module: null, offset: null };
    }
}

function captureBacktrace(context, limit) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .slice(0, limit || 14)
            .map(describe);
    } catch (_) {
        return [];
    }
}

function emit(kind, fields, tid) {
    if (eventCount >= MAX_EVENTS) return;
    eventCount++;
    var payload = fields || {};
    payload.event = kind;
    payload.elapsedMs = elapsed();
    payload.tid = tid === undefined ? Process.getCurrentThreadId() : tid;
    send({ jniDiagnostic: payload });
}

function remember(tid, kind, fields) {
    lastByThread[String(tid)] = {
        event: kind,
        elapsedMs: elapsed(),
        fields: fields
    };
}

var art = Process.getModuleByName('libart.so');
var artSymbols = art.enumerateSymbols();

function jniSymbols(operation) {
    var prefix = '_ZN3art3JNI' + operation.length + operation;
    return artSymbols.filter(function (symbol) {
        return !symbol.address.isNull() && symbol.name.indexOf(prefix) === 0;
    });
}

function firstJniAddress(operation) {
    var symbols = jniSymbols(operation);
    return symbols.length === 0 ? null : symbols[0].address;
}

function hookJni(operation, callbacksFactory) {
    var symbols = jniSymbols(operation);
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        var key = symbol.address.toString();
        if (hookedAddresses[key]) continue;
        hookedAddresses[key] = operation;
        try {
            var listener = Interceptor.attach(
                symbol.address,
                callbacksFactory(operation, symbol)
            );
            listeners.push(listener);
        } catch (error) {
            emit('hook-error', {
                operation: operation,
                symbol: symbol.name,
                address: key,
                error: String(error)
            });
        }
    }
    return symbols.length;
}

hookJni('FindClass', function () {
    return {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            this.name = safeCString(args[1]);
            this.caller = describe(this.returnAddress);
        },
        onLeave: function (retval) {
            var result = retval.toString();
            if (!retval.isNull() && this.name !== null) classNames[result] = this.name;
            var fields = { name: this.name, result: result, caller: this.caller };
            remember(this.tid, 'find-class', fields);
            if (retval.isNull() || (this.name && this.name.indexOf('pkbpqnzc') !== -1))
                emit('find-class', fields, this.tid);
        }
    };
});

['GetMethodID', 'GetStaticMethodID'].forEach(function (operation) {
    hookJni(operation, function () {
        return {
            onEnter: function (args) {
                this.tid = Process.getCurrentThreadId();
                this.classRef = args[1].toString();
                this.name = safeCString(args[2]);
                this.signature = safeCString(args[3]);
                this.caller = describe(this.returnAddress);
            },
            onLeave: function (retval) {
                var result = retval.toString();
                var fields = {
                    static: operation === 'GetStaticMethodID',
                    classRef: this.classRef,
                    className: classNames[this.classRef] || null,
                    name: this.name,
                    signature: this.signature,
                    result: result,
                    caller: this.caller
                };
                if (!retval.isNull()) methodNames[result] = fields;
                remember(this.tid, 'method-lookup', fields);
                var targetClass = fields.className !== null &&
                    fields.className.indexOf('pkbpqnzc') !== -1;
                if (retval.isNull() || targetClass || this.name === 'a')
                    emit('method-lookup', fields, this.tid);
            }
        };
    });
});

hookJni('NewStringUTF', function () {
    return {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            this.value = safeCString(args[1]);
            this.caller = describe(this.returnAddress);
        },
        onLeave: function (retval) {
            if (!retval.isNull() && this.value !== null)
                stringValues[retval.toString()] = this.value;
            if (this.value === '16') {
                emit('new-string-utf', {
                    value: this.value,
                    result: retval.toString(),
                    caller: this.caller
                }, this.tid);
            }
        }
    };
});

function callCallbacks(operation) {
    return {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            var methodId = args[2].toString();
            var method = methodNames[methodId] || null;
            var firstArgument = readFirstObjectArgument(operation, args);
            var fields = {
                operation: operation,
                classOrObject: args[1].toString(),
                methodId: methodId,
                method: method,
                firstArgument: firstArgument === null
                    ? null : firstArgument.toString(),
                firstArgumentString: firstArgument === null
                    ? null : (stringValues[firstArgument.toString()] || null),
                caller: describe(this.returnAddress),
                backtrace: captureBacktrace(this.context, 12)
            };
            remember(this.tid, 'jni-call', fields);
            // Calls from libart itself are implementation details.  Native
            // callers and all mapped methods are the useful JNI boundary.
            if (method !== null || fields.caller === null || fields.caller.module !== 'libart.so')
                emit('jni-call', fields, this.tid);
        }
    };
}

function readFirstObjectArgument(operation, args) {
    try {
        if (operation.endsWith('MethodA')) {
            if (args[3].isNull()) return null;
            return args[3].readPointer();
        }

        if (!operation.endsWith('MethodV')) {
            // The first unnamed argument is still register-backed at the
            // variadic JNI entry point and Frida exposes it as args[3].
            return args[3];
        }

        if (args[3].isNull()) return null;
        var vaList = args[3];
        if (Process.arch === 'x64') {
            // SysV __va_list_tag: gp_offset, fp_offset,
            // overflow_arg_area, reg_save_area.
            var gpOffset = vaList.readU32();
            var overflow = vaList.add(8).readPointer();
            var registers = vaList.add(16).readPointer();
            if (gpOffset < 48 && !registers.isNull())
                return registers.add(gpOffset).readPointer();
            return overflow.isNull() ? null : overflow.readPointer();
        }
        if (Process.arch === 'arm64') {
            // Bionic AArch64 va_list: stack, gr_top, vr_top, gr_offs,
            // vr_offs.  Integer/object arguments use the GR save area while
            // gr_offs is negative, then spill to stack.
            var stack = vaList.readPointer();
            var grTop = vaList.add(Process.pointerSize).readPointer();
            var grOffset = vaList.add(Process.pointerSize * 3).readS32();
            if (grOffset < 0 && !grTop.isNull())
                return grTop.add(grOffset).readPointer();
            return stack.isNull() ? null : stack.readPointer();
        }

        // On 32-bit x86/ARM, va_list is the address of the next stack slot.
        return vaList.readPointer();
    } catch (_) {
        return null;
    }
}

[
    'CallStaticVoidMethod', 'CallStaticVoidMethodV', 'CallStaticVoidMethodA',
    'CallVoidMethod', 'CallVoidMethodV', 'CallVoidMethodA'
].forEach(function (operation) {
    hookJni(operation, function () { return callCallbacks(operation); });
});

hookJni('ThrowNew', function () {
    return {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            this.fields = {
                classRef: args[1].toString(),
                className: classNames[args[1].toString()] || null,
                message: safeCString(args[2]),
                caller: describe(this.returnAddress),
                backtrace: captureBacktrace(this.context, 12)
            };
            remember(this.tid, 'throw-new', this.fields);
            emit('throw-new', this.fields, this.tid);
        },
        onLeave: function (retval) {
            this.fields.result = retval.toInt32();
        }
    };
});

hookJni('Throw', function () {
    return {
        onEnter: function (args) {
            var tid = Process.getCurrentThreadId();
            var fields = {
                throwable: args[1].toString(),
                caller: describe(this.returnAddress),
                backtrace: captureBacktrace(this.context, 12)
            };
            remember(tid, 'throw', fields);
            emit('throw', fields, tid);
        }
    };
});

hookJni('RegisterNatives', function (operation, symbol) {
    return {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            this.classRef = args[1].toString();
            this.caller = describe(this.returnAddress);
            this.symbol = symbol.name;
            this.methods = [];
            var count = 0;
            try { count = args[3].toInt32(); } catch (_) {}
            this.count = count;
            if (count <= 0 || count > 256 || args[2].isNull()) return;
            try {
                for (var i = 0; i < count; i++) {
                    var item = args[2].add(i * Process.pointerSize * 3);
                    var namePointer = item.readPointer();
                    var signaturePointer = item.add(Process.pointerSize).readPointer();
                    var implementation = item.add(Process.pointerSize * 2).readPointer();
                    this.methods.push({
                        name: safeCString(namePointer),
                        signature: safeCString(signaturePointer),
                        implementation: describe(implementation)
                    });
                }
            } catch (error) {
                this.methods.push({ parseError: String(error) });
            }
        },
        onLeave: function (retval) {
            var fields = {
                symbol: this.symbol,
                classRef: this.classRef,
                className: classNames[this.classRef] || null,
                count: this.count,
                methods: this.methods,
                result: retval.toInt32(),
                caller: this.caller
            };
            remember(this.tid, 'register-natives', fields);
            emit('register-natives', fields, this.tid);
        }
    };
});

var exceptionOccurredAddress = firstJniAddress('ExceptionOccurred');
var deleteLocalRefAddress = firstJniAddress('DeleteLocalRef');
var exceptionOccurred = exceptionOccurredAddress === null
    ? null
    : new NativeFunction(exceptionOccurredAddress, 'pointer', ['pointer']);
var deleteLocalRef = deleteLocalRefAddress === null
    ? null
    : new NativeFunction(deleteLocalRefAddress, 'void', ['pointer', 'pointer']);

hookJni('ExceptionCheck', function () {
    return {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            this.env = args[0];
            this.caller = describe(this.returnAddress);
            this.pendingAtEntry = null;
            this.backtrace = null;

            // Code16 is reported on the main thread.  Probing only that thread
            // keeps this diagnostic low-volume and avoids JNI work on unrelated
            // runtime threads.
            var tidKey = String(this.tid);
            if (this.tid !== Process.id || exceptionOccurred === null ||
                deleteLocalRef === null || probeDepth[tidKey]) return;
            probeDepth[tidKey] = true;
            try {
                var throwable = exceptionOccurred(this.env);
                if (!throwable.isNull()) {
                    this.pendingAtEntry = throwable.toString();
                    this.backtrace = captureBacktrace(this.context, 16);
                    deleteLocalRef(this.env, throwable);
                }
            } catch (error) {
                this.pendingAtEntry = 'probe-error: ' + String(error);
            } finally {
                delete probeDepth[tidKey];
            }
        },
        onLeave: function (retval) {
            // ART's C++ bool result is carried in AL on x86_64; upper RAX bits
            // are unspecified and otherwise turn every false check into noise.
            var result = retval.toInt32() & 0xff;
            if (this.pendingAtEntry === null && result === 0) return;
            emit('exception-check', {
                pendingAtEntry: this.pendingAtEntry,
                returnedValue: result,
                caller: this.caller,
                backtrace: this.backtrace || captureBacktrace(this.context, 16),
                previousEvent: lastByThread[String(this.tid)] || null
            }, this.tid);
        }
    };
});

hookJni('ExceptionClear', function () {
    return {
        onEnter: function () {
            var tid = Process.getCurrentThreadId();
            emit('exception-clear', {
                caller: describe(this.returnAddress),
                backtrace: captureBacktrace(this.context, 14),
                previousEvent: lastByThread[String(tid)] || null
            }, tid);
        }
    };
});

// Native-bridge libraries expose an x86 trampoline for the guest ARM64
// JNI_OnLoad.  Record whether execution returns and, if so, its exact version.
try {
    var nativeBridge = Process.getModuleByName('libnativebridge.so');
    var getTrampoline = nativeBridge.getExportByName(
        '_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j'
    );
    listeners.push(Interceptor.attach(getTrampoline, {
        onEnter: function (args) {
            this.name = safeCString(args[1]);
        },
        onLeave: function (retval) {
            if (this.name !== 'JNI_OnLoad' || retval.isNull()) return;
            var trampoline = retval;
            var key = trampoline.toString();
            if (hookedAddresses[key]) return;
            hookedAddresses[key] = 'JNI_OnLoad';
            try {
                listeners.push(Interceptor.attach(trampoline, {
                    onEnter: function () {
                        this.tid = Process.getCurrentThreadId();
                        emit('jni-onload-enter', {
                            trampoline: trampoline.toString(),
                            caller: describe(this.returnAddress)
                        }, this.tid);
                    },
                    onLeave: function (result) {
                        emit('jni-onload-leave', {
                            result: result.toInt32(),
                            resultHex: '0x' + result.toUInt32().toString(16)
                        }, this.tid);
                    }
                }));
            } catch (error) {
                emit('hook-error', {
                    operation: 'JNI_OnLoad',
                    address: key,
                    error: String(error)
                });
            }
        }
    }));
} catch (error) {
    emit('hook-error', {
        operation: 'NativeBridgeGetTrampoline',
        error: String(error)
    });
}

emit('ready', {
    traceWindowMs: TRACE_WINDOW_MS,
    listenerCount: listeners.length,
    exceptionOccurred: exceptionOccurredAddress === null
        ? null : exceptionOccurredAddress.toString(),
    deleteLocalRef: deleteLocalRefAddress === null
        ? null : deleteLocalRefAddress.toString()
});

setTimeout(function () {
    for (var i = 0; i < listeners.length; i++) {
        try { listeners[i].detach(); } catch (_) {}
    }
    emit('stopped', { capturedEvents: eventCount });
}, TRACE_WINDOW_MS);
