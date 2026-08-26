import Java from "frida-java-bridge";

const SHIELD_PACKAGE = "pkbpqnzc.";
const protectedPid = Process.id;

let nativeGuard: CModule | null = null;
let sentinelFaultCount = 0;
let reportGuardInstalled = false;
let reportGuardInstalling = false;
const guardStatus = {
    installed: false,
    directGuardInstalled: false,
    directAttempts: 0,
    suppressed: false,
    className: null as string | null,
    message: null as string | null,
    detail: null as string | null,
};

function installReportGuardFor(loader: Java.Wrapper): void {
    if (reportGuardInstalled || reportGuardInstalling) return;
    reportGuardInstalling = true;
    try {
        const factory = Java.ClassFactory.get(loader);
        const Report = factory.use("pkbpqnzc.aG");
        const report = Report.a.overload("java.lang.String");
        report.implementation = function (code: Java.Wrapper) {
            guardStatus.suppressed = true;
            guardStatus.className = "pkbpqnzc.aG";
            guardStatus.message = code === null ? "" : code.toString();
            guardStatus.detail = "direct protection report suppressed";
            send(`[JAVA-GUARD] protection report suppressed: ${code}`);
            try {
                Java.vm.getEnv().exceptionClear();
            } catch (_) {}
        };
        reportGuardInstalled = true;
        guardStatus.directGuardInstalled = true;
        send("[JAVA-GUARD] direct report guard ready");
    } catch (error) {
        guardStatus.detail = `direct report guard pending: ${error}`;
    } finally {
        reportGuardInstalling = false;
    }
}

function discoverReportGuard(): void {
    if (reportGuardInstalled || !Java.available) return;
    Java.performNow(() => {
        guardStatus.directAttempts++;
        const loaders = Java.enumerateClassLoadersSync();
        for (const loader of loaders) {
            installReportGuardFor(loader);
            if (reportGuardInstalled) return;
        }
    });
}

function installSentinelFaultGuard(): void {
    Process.setExceptionHandler((details) => {
        try {
            const memory = details.memory;
            if (
                details.type !== "access-violation" ||
                memory === undefined ||
                memory.address.compare(ptr("0x7fff0000")) < 0 ||
                memory.address.compare(ptr("0x80010000")) > 0 ||
                sentinelFaultCount >= 64
            ) {
                return false;
            }

            sentinelFaultCount++;
            const context = details.context as CpuContext & {
                pc: NativePointer;
                sp: NativePointer;
                rax?: NativePointer;
            };
            const faultPc = context.pc;
            const instruction = Instruction.parse(faultPc);
            const module = Process.findModuleByAddress(faultPc);
            const location = module === null
                ? "unknown"
                : `${module.name}+${faultPc.sub(module.base)}`;
            send(
                `[FAULT-GUARD] sentinel #${sentinelFaultCount} ` +
                `address=${memory.address} pc=${faultPc} ` +
                `op=${memory.operation} at=${location} insn=${instruction}`
            );

            // A branch to the sentinel has to be unwound like a normal return.
            // A load/store touching it can safely be skipped instruction-wise.
            if (faultPc.equals(memory.address) && Process.arch === "x64") {
                context.pc = context.sp.readPointer();
                context.sp = context.sp.add(Process.pointerSize);
            } else {
                if (Process.arch === "x64" && context.rax !== undefined) {
                    context.rax = ptr(0);
                }
                context.pc = instruction.next;
            }
            return true;
        } catch (error) {
            send(`[FAULT-GUARD] recovery failed: ${error}`);
            return false;
        }
    });
    send("[FAULT-GUARD] ready");
}

function findLibcExport(name: string): NativePointer | null {
    try {
        return Process.getModuleByName("libc.so").getExportByName(name);
    } catch (_) {
        return null;
    }
}

function installNativeTerminationGuard(): void {
    const killAddress = findLibcExport("kill");
    const tgkillAddress = findLibcExport("tgkill");
    const ptraceAddress = findLibcExport("ptrace");
    if (killAddress === null || tgkillAddress === null || ptraceAddress === null) {
        send("[NATIVE-GUARD] required libc exports are unavailable");
        return;
    }

    const source = `
        #include <stdint.h>

        extern int original_kill(int pid, int sig);
        extern int original_tgkill(int tgid, int tid, int sig);
        extern long original_ptrace(long request, long pid, void *addr, void *data);

        #define PROTECTED_PID ${protectedPid}
        #define PTRACE_CONT 7
        #define PTRACE_KILL 8
        #define PTRACE_SINGLESTEP 9

        static int is_fatal_signal(long sig) {
            return sig == 6 || sig == 9 || sig == 11;
        }

        int guarded_kill(int pid, int sig) {
            if ((pid == PROTECTED_PID || pid == 0) && is_fatal_signal(sig))
                return 0;
            return original_kill(pid, sig);
        }

        int guarded_tgkill(int tgid, int tid, int sig) {
            if (tgid == PROTECTED_PID && is_fatal_signal(sig))
                return 0;
            return original_tgkill(tgid, tid, sig);
        }

        long guarded_ptrace(long request, long pid, void *addr, void *data) {
            long sig = (long) data;
            if (pid == PROTECTED_PID) {
                if (request == PTRACE_KILL)
                    return 0;
                if ((request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
                    is_fatal_signal(sig))
                    data = 0;
            }
            return original_ptrace(request, pid, addr, data);
        }
    `;

    try {
        nativeGuard = new CModule(source, {
            original_kill: killAddress,
            original_tgkill: tgkillAddress,
            original_ptrace: ptraceAddress,
        });
        Interceptor.replace(killAddress, nativeGuard.guarded_kill);
        Interceptor.replace(tgkillAddress, nativeGuard.guarded_tgkill);
        Interceptor.replace(ptraceAddress, nativeGuard.guarded_ptrace);
        send(`[NATIVE-GUARD] ready for PID ${protectedPid}`);
    } catch (error) {
        send(`[NATIVE-GUARD] setup failed: ${error}`);
    }
}

function installShieldExceptionGuard(): void {
    if (!Java.available) {
        send("[JAVA-GUARD] ART is not available");
        return;
    }

    // This only touches a boot-class method, so it can be installed while the
    // spawned app is still suspended. Java.perform() waits for the app class
    // loader and would lose the race with the protection's JNI_OnLoad path.
    Java.performNow(() => {
        try {
            const ClassLoader = Java.use("java.lang.ClassLoader");
            const loadClass = ClassLoader.loadClass.overload(
                "java.lang.String",
                "boolean"
            );
            loadClass.implementation = function (name: Java.Wrapper, resolve: boolean) {
                const loaded = loadClass.call(this, name, resolve);
                if (name.toString() === "pkbpqnzc.aG") {
                    installReportGuardFor(this);
                }
                return loaded;
            };

            const loadClassSimple = ClassLoader.loadClass.overload("java.lang.String");
            loadClassSimple.implementation = function (name: Java.Wrapper) {
                const loaded = loadClassSimple.call(this, name);
                if (name.toString() === "pkbpqnzc.aG") {
                    installReportGuardFor(this);
                }
                return loaded;
            };

            const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
            const findClass = BaseDexClassLoader.findClass.overload("java.lang.String");
            findClass.implementation = function (name: Java.Wrapper) {
                const loaded = findClass.call(this, name);
                if (name.toString() === "pkbpqnzc.aG") {
                    installReportGuardFor(this);
                }
                return loaded;
            };

            const KillApplicationHandler = Java.use(
                "com.android.internal.os.RuntimeInit$KillApplicationHandler"
            );
            const uncaughtException = KillApplicationHandler.uncaughtException.overload(
                "java.lang.Thread",
                "java.lang.Throwable"
            );

            uncaughtException.implementation = function (thread: Java.Wrapper, error: Java.Wrapper) {
                let className = "";
                let message = "";

                try {
                    className = error.getClass().getName().toString();
                } catch (_) {}
                try {
                    const value = error.getMessage();
                    message = value === null ? "" : value.toString();
                } catch (_) {}

                send(`[JAVA-GUARD] uncaught ${className}: ${message}`);
                if (className.startsWith(SHIELD_PACKAGE)) {
                    guardStatus.suppressed = true;
                    guardStatus.className = className;
                    guardStatus.message = message;
                    guardStatus.detail =
                        "protection exception returned without invoking app kill";
                    try {
                        Java.vm.getEnv().exceptionClear();
                    } catch (_) {}
                    send("[JAVA-GUARD] protection exception suppressed");
                    return;
                }

                return uncaughtException.call(this, thread, error);
            };

            guardStatus.installed = true;
            guardStatus.detail = "selective Java report guard installed";
            send("[JAVA-GUARD] ready");
        } catch (error) {
            guardStatus.detail = String(error);
            send(`[JAVA-GUARD] setup failed: ${error}`);
        }
    });
}

installShieldExceptionGuard();
installSentinelFaultGuard();
discoverReportGuard();
const directGuardStartedAt = Date.now();
const directGuardTimer = setInterval(() => {
    try {
        discoverReportGuard();
    } catch (error) {
        guardStatus.detail = `direct report guard retry failed: ${error}`;
    }
    if (reportGuardInstalled || Date.now() - directGuardStartedAt > 10000) {
        clearInterval(directGuardTimer);
        if (!reportGuardInstalled)
            send(`[JAVA-GUARD] direct report guard timed out: ${guardStatus.detail}`);
    }
}, 5);

rpc.exports = {
    status() {
        return guardStatus;
    },
};
