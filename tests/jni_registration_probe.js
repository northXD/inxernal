'use strict';

// Read-only, low-overhead tracer for the protection bootstrap's single
// RegisterNatives entry.  Kept separate so timing-sensitive startup code is
// not perturbed by the full JNI diagnostic payload.
var art = Process.getModuleByName('libart.so');
var listeners = [];
var startedAt = Date.now();

function emit(event, fields) {
    fields.event = event;
    fields.elapsedMs = Date.now() - startedAt;
    send({ registrationProbe: fields });
}

art.enumerateSymbols().forEach(function (symbol) {
    if (symbol.address.isNull()) return;
    if (symbol.name.indexOf('RegisterNatives') !== -1 &&
        symbol.name.indexOf('UnregisterNatives') === -1) {
        try {
            listeners.push(Interceptor.attach(symbol.address, {
                onEnter: function (args) {
                    this.env = args[0];
                    this.clazz = args[1];
                    this.table = args[2];
                    this.count = args[3].toInt32();
                    this.target = false;
                    this.methods = [];
                    if (this.count <= 0 || this.count > 16 || this.table.isNull())
                        return;
                    try {
                        for (var i = 0; i < this.count; i++) {
                            var row = this.table.add(i * Process.pointerSize * 3);
                            var name = row.readPointer().readCString();
                            var signature = row.add(Process.pointerSize)
                                .readPointer().readCString();
                            var implementation = row.add(Process.pointerSize * 2)
                                .readPointer();
                            this.methods.push({
                                name: name,
                                signature: signature,
                                implementation: implementation.toString()
                            });
                            if (name === 'a' &&
                                signature === '(Ljava/lang/Class;I)V')
                                this.target = true;
                        }
                    } catch (_) {
                        this.methods = [];
                    }
                },
                onLeave: function (retval) {
                    if (!this.target) return;
                    emit('register-q', {
                        symbol: symbol.name,
                        env: this.env.toString(),
                        clazz: this.clazz.toString(),
                        table: this.table.toString(),
                        count: this.count,
                        methods: this.methods,
                        result: retval.toInt32()
                    });
                }
            }));
        } catch (_) {}
    } else if (symbol.name.indexOf('UnregisterNatives') !== -1) {
        try {
            listeners.push(Interceptor.attach(symbol.address, {
                onEnter: function (args) {
                    emit('unregister', {
                        symbol: symbol.name,
                        env: args[0].toString(),
                        clazz: args[1].toString()
                    });
                }
            }));
        } catch (_) {}
    }
});

emit('ready', { listenerCount: listeners.length });
