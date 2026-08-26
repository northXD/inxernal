// =============================================================================
//  quago_probe.ts  -  Quago anti-cheat module for Hay Day (frida-compiled, ships
//  its own frida-java-bridge like java_guard). Loaded by the loader when
//  NX_QUAGO=1. Two jobs:
//
//   1) EMULATE: inject realistic ~20Hz hand-held ACCELEROMETER motion into ONLY
//      Quago's listener (com.quago.mobile.sdk.e.onSensorChanged), so Quago's ML
//      sees a human holding a phone instead of a flat emulator. Save/restore the
//      event values around the call so other sensor listeners are unaffected.
//      Toggle with rpc setSpoof(); default ON.
//
//   2) STATE FEED: capture the QuagoManager telemetry (beginSegment = current
//      screen, setKeyValue = PlayerId/Name/FarmLevel/sell details) into a dict
//      exposed to the loader via rpc.exports.state()  ->  the `nstate` command.
//
//  Logs (send + logcat tag QUAGOPROBE) key events; full method spam is off.
//  Build:  npm run build:quago
// =============================================================================
import Java from "frida-java-bridge";

// ---- logging: console (send) + logcat ---------------------------------------
let logwrite: any = null;
let logTag: NativePointer | null = null;
function ensureLog(): void {
    if (logwrite) return;
    try {
        const mod = Process.findModuleByName("liblog.so");
        const p = mod ? mod.findExportByName("__android_log_write") : null;
        if (p) logwrite = new NativeFunction(p, "int", ["int", "pointer", "pointer"]);
        if (logTag === null) logTag = Memory.allocUtf8String("QUAGOPROBE");
    } catch (_) {}
}
function log(m: string): void {
    try { send("[QUAGO] " + m); } catch (_) {}
    try { ensureLog(); if (logwrite) logwrite(4, logTag, Memory.allocUtf8String(String(m))); } catch (_) {}
}

// ---- shared state ------------------------------------------------------------
// PRIMARY approach: BLOCK the report upload to api.quago.io (Quago collects but
// its ML server gets nothing - no data to classify, and no fake data that could
// ever look inconsistent). Accel emulation is kept but OFF by default.
let blockOn = true;                 // block api.quago.io uploads (the chosen approach)
let spoofOn = false;                // accelerometer emulation (optional, off)
let blockInstalled = false;
let blockedCount = 0;
const gameState: { [k: string]: string } = { segment: "", _updated: "0" };
let stateVer = 0;
let accelHooked = false;
let accelLogged = 0;
let qmHooked = false;
let rootHooked = false;
let sensorLogged = false;

// ---- realistic hand-held accelerometer generator (m/s^2) --------------------
// Base gravity vector at a plausible viewing tilt, slow drift (random walk),
// hand tremor (~9Hz), gaussian micro-noise, and occasional small repositions.
// |a| stays ~9.81 so it reads as a real device held in a hand, not a static rig.
let bx = 0.6, by = 4.2;             // tilt components (bz derived to keep |g|~9.81)
let phase = 0;
let moveTtl = 0, mvx = 0, mvy = 0, mvz = 0;
function gauss(): number {
    return (Math.random() + Math.random() + Math.random() + Math.random() - 2) * 0.5;
}
function genAccel(): number[] {
    phase += 0.05;                                   // ~20Hz
    bx += gauss() * 0.02; by += gauss() * 0.02;      // slow tilt drift
    if (bx < -3) bx = -3; if (bx > 3) bx = 3;
    if (by < 1.5) by = 1.5; if (by > 7.5) by = 7.5;
    let bz2 = 96.2 - bx * bx - by * by;              // 9.81^2 ~= 96.2
    const bz = Math.sqrt(bz2 > 1 ? bz2 : 1);
    const tremor = 0.06 * Math.sin(2 * Math.PI * 9 * phase);
    if (moveTtl <= 0 && Math.random() < 0.012) {     // occasional micro-reposition
        moveTtl = 3 + Math.floor(Math.random() * 6);
        mvx = gauss() * 0.6; mvy = gauss() * 0.6; mvz = gauss() * 0.4;
    }
    let ex = 0, ey = 0, ez = 0;
    if (moveTtl > 0) { ex = mvx; ey = mvy; ez = mvz; moveTtl--; mvx *= 0.7; mvy *= 0.7; mvz *= 0.7; }
    return [bx + tremor + gauss() * 0.05 + ex,
            by + tremor * 0.7 + gauss() * 0.05 + ey,
            bz + gauss() * 0.05 + ez];
}

// ---- native root detection: retry until libQuagoTool.so is mapped -----------
function hookRoot(): void {
    if (rootHooked) return;
    try {
        const mod = Process.findModuleByName("libQuagoTool.so");
        if (mod === null) return;
        const fn = mod.getExportByName(
            "Java_com_quago_mobile_sdk_root_QuagoRootDetectionNative_checkForRoot");
        Interceptor.attach(fn, {
            onLeave(r) { log("native checkForRoot() -> " + r + " (nonzero=rooted)"); },
        });
        rootHooked = true;
        log("hooked native checkForRoot @ " + fn);
    } catch (_) {}
}

// ---- log which sensors are subscribed (once, for confirmation) --------------
function hookSensorLog(): void {
    if (sensorLogged) return;
    try {
        const SM: any = Java.use("android.hardware.SensorManager");
        SM.registerListener.overloads.forEach((ov: any) => {
            ov.implementation = function (...args: any[]) {
                try {
                    let s: any = null, rate = -1, l: any = null;
                    for (const a of args) {
                        const cn = a && a.$className;
                        if (cn === "android.hardware.Sensor") s = a;
                        else if (typeof a === "number" && rate < 0) rate = a;
                        else if (cn && l === null && cn.indexOf("Sensor") < 0) l = a;
                    }
                    const who = l ? l.$className : "?";
                    if (who.indexOf("quago") >= 0)
                        log("QUAGO subscribes sensor=" + (s ? s.getName() + " type=" + s.getType() : "?") +
                            " rate=" + rate + " listener=" + who);
                } catch (_) {}
                return ov.apply(this, args);
            };
        });
        sensorLogged = true;
    } catch (_) {}
}

// ---- BLOCK the Quago report upload (java.net.URL.openConnection -> dead) -----
// Quago posts to https://api.quago.io/v1/record via java.net.URL. Redirect those
// opens to a dead local endpoint so the upload fails silently (Quago handles the
// network error gracefully); its ML server gets nothing to classify us with.
function hookBlock(): void {
    if (blockInstalled) return;
    try {
        const URL: any = Java.use("java.net.URL");
        URL.openConnection.overloads.forEach((ov: any) => {
            ov.implementation = function (this: any, ...a: any[]) {
                try {
                    const u = this.toString();
                    if (/quago/i.test(u)) {
                        if (blockOn) {
                            blockedCount++;
                            if (blockedCount <= 5 || blockedCount % 50 === 0)
                                log("BLOCKED Quago upload #" + blockedCount + " " + u);
                            return URL.$new("http://127.0.0.1:1/").openConnection();
                        }
                        log("Quago upload ALLOWED " + u);
                    }
                } catch (_) {}
                return ov.apply(this, a);
            };
        });
        blockInstalled = true;
        log("upload block armed (blockOn=" + blockOn + ")");
    } catch (e) { log("block hook err: " + e); }
}

// ---- accelerometer emulation: hook Quago's listener onSensorChanged ---------
function hookAccel(factory: any): void {
    if (accelHooked) return;
    try {
        const E: any = factory.use("com.quago.mobile.sdk.e");
        E.onSensorChanged.overload("android.hardware.SensorEvent").implementation =
            function (this: any, event: any) {
                if (spoofOn) {
                    try {
                        const vf = event.values;
                        const arr = vf.value;                 // float[]
                        if (arr && arr.length >= 3) {
                            const o0 = arr[0], o1 = arr[1], o2 = arr[2];
                            const s = genAccel();
                            if (accelLogged < 3) {
                                accelLogged++;
                                log("accel orig=[" + o0.toFixed(2) + "," + o1.toFixed(2) + "," + o2.toFixed(2) +
                                    "] -> spoof=[" + s[0].toFixed(2) + "," + s[1].toFixed(2) + "," + s[2].toFixed(2) + "]");
                            }
                            arr[0] = s[0]; arr[1] = s[1]; arr[2] = s[2];
                            vf.value = arr;                   // write spoofed values
                            const r = this.onSensorChanged(event);
                            arr[0] = o0; arr[1] = o1; arr[2] = o2;
                            vf.value = arr;                   // restore for other listeners
                            return r;
                        }
                    } catch (_) {}
                }
                return this.onSensorChanged(event);
            };
        accelHooked = true;
        log("ACCEL EMULATION active on com.quago.mobile.sdk.e.onSensorChanged (spoofOn=" + spoofOn + ")");
    } catch (_) {}
}

// ---- game-state capture from QuagoManager -----------------------------------
function hookQuagoManager(factory: any): void {
    if (qmHooked) return;
    try {
        const QM: any = factory.use("com.supercell.titan.QuagoManager");
        try {
            QM.beginSegment.overloads.forEach((ov: any) => {
                ov.implementation = function (this: any, seg: any) {
                    try { gameState.segment = String(seg); gameState._updated = String(++stateVer);
                          log("segment -> " + seg); } catch (_) {}
                    return ov.apply(this, arguments as any);
                };
            });
        } catch (_) {}
        try {
            QM.endSegment.overloads.forEach((ov: any) => {
                ov.implementation = function (this: any) {
                    try { gameState.segment = ""; gameState._updated = String(++stateVer); } catch (_) {}
                    return ov.apply(this, arguments as any);
                };
            });
        } catch (_) {}
        try {
            QM.setKeyValue.overload("java.lang.String", "java.lang.String").implementation =
                function (this: any, k: any, v: any) {
                    try { gameState[String(k)] = String(v); gameState._updated = String(++stateVer); } catch (_) {}
                    return this.setKeyValue(k, v);
                };
        } catch (_) {}
        try {
            QM.enable.overloads.forEach((ov: any) => {
                ov.implementation = function (this: any) {
                    log("QuagoManager.enable(" + Array.prototype.slice.call(arguments).join(",") + ")");
                    return ov.apply(this, arguments as any);
                };
            });
        } catch (_) {}
        qmHooked = true;
        log("hooked QuagoManager (state feed + enable)");
    } catch (_) {}
}

// ---- driver: retry until ART + the classes are present ----------------------
let tries = 0;
const timer = setInterval(() => {
    tries++;
    hookRoot();
    if (!Java.available) { if (tries % 20 === 0) log("waiting for ART (" + tries + ")"); if (tries > 300) clearInterval(timer); return; }
    Java.performNow(() => {
        hookSensorLog();
        hookBlock();
        if (!qmHooked || !accelHooked) {
            const loaders = Java.enumerateClassLoadersSync();
            for (const loader of loaders) {
                let f: any;
                try { f = Java.ClassFactory.get(loader); } catch (_) { continue; }
                hookQuagoManager(f);
                hookAccel(f);
            }
        }
        if (qmHooked && blockInstalled) { log("quago module settled (block armed; tries=" + tries + ")"); clearInterval(timer); }
        else if (tries > 300) { log("quago module partial (qm=" + qmHooked + " block=" + blockInstalled + " accel=" + accelHooked + ")"); clearInterval(timer); }
    });
}, 250);

// ---- RPC for the loader (nstate / nquago spoof) -----------------------------
rpc.exports = {
    state(): any { return gameState; },
    setBlock(on: boolean): boolean { blockOn = !!on; log("upload block -> " + blockOn); return blockOn; },
    setSpoof(on: boolean): boolean { spoofOn = !!on; log("accel spoof -> " + spoofOn); return spoofOn; },
    status(): any { return { blockOn, blockedCount, spoofOn, accelHooked, qmHooked, blockInstalled, rootHooked, stateVer }; },
};

log("quago module loaded (block upload + state feed; accel emulate optional)");
