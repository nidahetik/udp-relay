#!/usr/bin/env node
'use strict';

const net = require('node:net');
const http = require('node:http');
const dgram = require('node:dgram');
const dns = require('node:dns').promises;

const CONFIG = Object.freeze({
    LISTEN_HOST: '0.0.0.0',
    LISTEN_PORT: Number(process.env.PORT) || 8443,
    HANDSHAKE_TIMEOUT_MS: 10000,
    IDLE_TIMEOUT_MS: 300000,
    XUDP_GRACE_MS: 60000,
    MAX_CONNECTIONS: 4096,
    LOG_RING_SIZE: 500,
    REJECT_UDP_443: false,
});

const RELAY_MAGIC = Buffer.from('VLRLY004', 'ascii');
const RELAY_MODE_FIXED_UDP = 0x01;
const RELAY_MODE_MUX = 0x02;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6 = 0x03;
const MUX_STATUS_NEW = 0x01;
const MUX_STATUS_KEEP = 0x02;
const MUX_STATUS_END = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA = 0x01;
const MUX_OPTION_ERROR = 0x02;
const MUX_NETWORK_UDP = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_PACKET_LEN = 65535;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

function rejectUdpTarget(target) {
    return Boolean(CONFIG.REJECT_UDP_443 && Number(target?.port) === 443);
}

const stats = {
    activeConnections: 0, 
    udpBytesOut: 0,       
    udpBytesIn: 0,
    udpPacketsOut: 0,
    udpPacketsIn: 0,
};
const activeUdpAssociations = new Set(); 
let nextConnId = 1;

const logRing = [];
const logSubscribers = new Set();
let logSeq = 0;
function logEvent(level, message, kind = level) {
    const entry = { id: ++logSeq, ts: Date.now(), level, kind, message };
    logRing.push(entry);
    if (logRing.length > CONFIG.LOG_RING_SIZE) logRing.shift();
    const line = `[${new Date(entry.ts).toISOString()}] ${level.toUpperCase().padEnd(5)} ${message}`;
    if (level === 'error') console.error(line);
    else console.log(line);
    for (const send of logSubscribers) {
        try { send(entry); } catch {}
    }
}

const READER_HIGH_WATER = 1024 * 1024;
const READER_LOW_WATER = 256 * 1024;

class AsyncByteReader {
    constructor(socket, onBytes) {
        this.socket = socket;
        this.buffers = [];
        this.available = 0;
        this.waiters = [];
        this.ended = false;
        this.error = null;
        this.paused = false;
        socket.on('data', (chunk) => {
            if (!chunk || chunk.length === 0) return;
            if (onBytes) onBytes(chunk.length);
            this.buffers.push(Buffer.from(chunk));
            this.available += chunk.length;
            this._flush();
            if (!this.paused && this.available > READER_HIGH_WATER) {
                this.paused = true;
                socket.pause();
            }
        });
        socket.on('end', () => { this.ended = true; this._flush(); });
        socket.on('close', () => { this.ended = true; this._flush(); });
        socket.on('error', (err) => { this.error = err; this._flush(); });
    }
    readExactly(length) {
        if (!Number.isInteger(length) || length < 0) return Promise.reject(new Error('invalid read length'));
        if (length === 0) return Promise.resolve(Buffer.alloc(0));
        if (this.available >= length) return Promise.resolve(this._take(length));
        if (this.error) return Promise.reject(this.error);
        if (this.ended) return Promise.reject(new Error('unexpected EOF'));
        return new Promise((resolve, reject) => { this.waiters.push({ length, resolve, reject }); });
    }
    _flush() {
        while (this.waiters.length > 0) {
            const waiter = this.waiters[0];
            if (this.available >= waiter.length) {
                this.waiters.shift();
                waiter.resolve(this._take(waiter.length));
                continue;
            }
            if (this.error || this.ended) {
                this.waiters.shift();
                waiter.reject(this.error || new Error('unexpected EOF'));
                continue;
            }
            break;
        }
    }
    _take(length) {
        const out = Buffer.allocUnsafe(length);
        let offset = 0;
        while (offset < length) {
            const first = this.buffers[0];
            const need = length - offset;
            if (first.length <= need) {
                first.copy(out, offset);
                offset += first.length;
                this.buffers.shift();
            } else {
                first.copy(out, offset, 0, need);
                this.buffers[0] = first.subarray(need);
                offset += need;
            }
        }
        this.available -= length;
        if (this.paused && this.available < READER_LOW_WATER) {
            this.paused = false;
            this.socket.resume();
        }
        return out;
    }
}

async function readLengthPayload(reader) {
    const lenBuf = await reader.readExactly(2);
    const length = lenBuf.readUInt16BE(0);
    return length === 0 ? Buffer.alloc(0) : reader.readExactly(length);
}

async function readEndpoint(reader) {
    const head = await reader.readExactly(3);
    const port = head.readUInt16BE(0);
    const atyp = head[2];
    if (port === 0) throw new Error('zero port');
    return readEndpointBody(reader, atyp, port);
}

async function readEndpointBody(reader, atyp, port) {
    if (atyp === ATYP_IPV4) {
        const b = await reader.readExactly(4);
        return { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp };
    }
    if (atyp === ATYP_DOMAIN) {
        const len = (await reader.readExactly(1))[0];
        if (len === 0) throw new Error('empty domain');
        const b = await reader.readExactly(len);
        let host;
        try { host = utf8Fatal.decode(b); } catch { throw new Error('invalid UTF-8 domain'); }
        if (!host) throw new Error('empty domain');
        return { host, port, atyp };
    }
    if (atyp === ATYP_IPV6) {
        const b = await reader.readExactly(16);
        return { host: formatIPv6(b), port, atyp };
    }
    throw new Error(`unknown address type ${atyp}`);
}

function parseEndpointBytes(buffer, offset) {
    if (offset < 0 || buffer.length - offset < 3) throw new Error('unexpected EOF in endpoint');
    const port = buffer.readUInt16BE(offset);
    if (port === 0) throw new Error('zero port');
    const atyp = buffer[offset + 2];
    let cursor = offset + 3;
    if (atyp === ATYP_IPV4) {
        if (buffer.length - cursor < 4) throw new Error('unexpected EOF in IPv4');
        const b = buffer.subarray(cursor, cursor + 4);
        cursor += 4;
        return { endpoint: { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp }, next: cursor };
    }
    if (atyp === ATYP_DOMAIN) {
        if (buffer.length - cursor < 1) throw new Error('unexpected EOF in domain length');
        const len = buffer[cursor++];
        if (len === 0 || buffer.length - cursor < len) throw new Error('invalid domain length');
        let host;
        try { host = utf8Fatal.decode(buffer.subarray(cursor, cursor + len)); } catch { throw new Error('invalid UTF-8 domain'); }
        cursor += len;
        return { endpoint: { host, port, atyp }, next: cursor };
    }
    if (atyp === ATYP_IPV6) {
        if (buffer.length - cursor < 16) throw new Error('unexpected EOF in IPv6');
        const host = formatIPv6(buffer.subarray(cursor, cursor + 16));
        cursor += 16;
        return { endpoint: { host, port, atyp }, next: cursor };
    }
    throw new Error(`unknown address type ${atyp}`);
}

function formatIPv6(bytes) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
    return parts.join(':');
}

function ipv6ToBytes(address) {
    let input = address;
    const zone = input.indexOf('%');
    if (zone >= 0) input = input.slice(0, zone);
    let ipv4Tail = null;
    const lastColon = input.lastIndexOf(':');
    if (input.includes('.') && lastColon >= 0) {
        const ipv4 = input.slice(lastColon + 1).split('.').map(Number);
        if (ipv4.length !== 4 || ipv4.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
            throw new Error(`invalid IPv6 address: ${address}`);
        }
        ipv4Tail = [((ipv4[0] << 8) | ipv4[1]).toString(16), ((ipv4[2] << 8) | ipv4[3]).toString(16)];
        input = input.slice(0, lastColon) + ':' + ipv4Tail.join(':');
    }
    const halves = input.split('::');
    if (halves.length > 2) throw new Error(`invalid IPv6 address: ${address}`);
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
        throw new Error(`invalid IPv6 address: ${address}`);
    }
    const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
    if (words.length !== 8) throw new Error(`invalid IPv6 address: ${address}`);
    const out = Buffer.alloc(16);
    words.forEach((word, i) => {
        if (!/^[0-9a-f]{1,4}$/i.test(word)) throw new Error(`invalid IPv6 address: ${address}`);
        out.writeUInt16BE(parseInt(word, 16), i * 2);
    });
    return out;
}

function encodeUDPSource(rinfo) {
    const port = Number(rinfo.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid UDP source port');
    const family = net.isIP(rinfo.address);
    const head = Buffer.alloc(3);
    head.writeUInt16BE(port, 0);
    if (family === 4) {
        head[2] = ATYP_IPV4;
        return Buffer.concat([head, Buffer.from(rinfo.address.split('.').map(Number))]);
    }
    if (family === 6) {
        head[2] = ATYP_IPV6;
        return Buffer.concat([head, ipv6ToBytes(rinfo.address)]);
    }
    throw new Error(`invalid UDP source IP: ${rinfo.address}`);
}

function writeSocket(socket, data, conn) {
    if (socket.destroyed || !socket.writable) return Promise.reject(new Error('socket is closed'));
    if (conn) conn.bytesOut += data.length;
    return new Promise((resolve, reject) => {
        socket.write(data, (err) => (err ? reject(err) : resolve()));
    });
}

async function writeControlError(socket, message) {
    let body = Buffer.from(String(message || 'relay error'), 'utf8');
    if (body.length > MAX_PACKET_LEN) body = body.subarray(0, MAX_PACKET_LEN);
    const out = Buffer.allocUnsafe(3 + body.length);
    out[0] = 1;
    out.writeUInt16BE(body.length, 1);
    body.copy(out, 3);
    try { await writeSocket(socket, out); } catch {}
}

async function readControl(reader) {
    const magic = await reader.readExactly(RELAY_MAGIC.length);
    if (!magic.equals(RELAY_MAGIC)) throw new Error('bad magic');
    const mode = (await reader.readExactly(1))[0];
    if (![RELAY_MODE_FIXED_UDP, RELAY_MODE_MUX].includes(mode)) throw new Error('bad mode');
    const target = mode === RELAY_MODE_FIXED_UDP ? await readEndpoint(reader) : null;
    return { mode, target };
}

const RESOLVE_TTL_MS = 30000;
const RESOLVE_CACHE_MAX = 512;
const resolveCache = new Map(); 

async function lookupOnce(host) {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    if (!records.length) throw new Error(`DNS returned no address for ${host}`);
    const preferred = records.find((r) => r.family === 4) || records.find((r) => r.family === 6);
    if (!preferred) throw new Error(`DNS returned unsupported address for ${host}`);
    return preferred;
}

async function resolveTarget(target) {
    if (target.atyp === ATYP_IPV4) return { address: target.host, family: 4 };
    if (target.atyp === ATYP_IPV6) return { address: target.host, family: 6 };
    const key = target.host.toLowerCase();
    const hit = resolveCache.get(key);
    if (hit) {
        if (hit.pending) return hit.pending;
        if (hit.expires > Date.now()) return hit.value;
        resolveCache.delete(key);
    }
    const pending = lookupOnce(target.host);
    resolveCache.set(key, { pending });
    try {
        const value = await pending;
        resolveCache.delete(key); 
        resolveCache.set(key, { value, expires: Date.now() + RESOLVE_TTL_MS });
        while (resolveCache.size > RESOLVE_CACHE_MAX) resolveCache.delete(resolveCache.keys().next().value);
        return value;
    } catch (err) {
        if (resolveCache.get(key)?.pending === pending) resolveCache.delete(key);
        throw err;
    }
}

function bindDgram(socket, port, address) {
    return new Promise((resolve, reject) => {
        const onError = (err) => { cleanup(); reject(err); };
        const onListening = () => { cleanup(); resolve(); };
        const cleanup = () => { socket.off('error', onError); socket.off('listening', onListening); };
        socket.once('error', onError);
        socket.once('listening', onListening);
        socket.bind(port, address);
    });
}

class UDPAssociation {
    constructor() {
        this.udp4 = null;
        this.udp6 = null;
        this.port = 0;
        this.sink = null;
        this.closed = false;
    }
    static async create() {
        const assoc = new UDPAssociation();
        assoc.udp4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await bindDgram(assoc.udp4, 0, '0.0.0.0');
        assoc.port = assoc.udp4.address().port;
        assoc.udp4.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
        assoc.udp4.on('error', () => {});
        assoc.udp6 = dgram.createSocket({ type: 'udp6', reuseAddr: true, ipv6Only: true });
        try {
            await bindDgram(assoc.udp6, assoc.port, '::');
            assoc.udp6.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
            assoc.udp6.on('error', () => {});
        } catch {
            try { assoc.udp6.close(); } catch {}
            assoc.udp6 = null;
        }
        activeUdpAssociations.add(assoc);
        return assoc;
    }
    attach(sink) {
        const old = this.sink;
        this.sink = sink;
        return old;
    }
    detach(mux, id) {
        if (this.sink && this.sink.mux === mux && this.sink.id === id) {
            this.sink = null;
            return true;
        }
        return false;
    }
    async send(target, payload) {
        if (this.closed) throw new Error('UDP association is closed');
        if (payload.length > MAX_PACKET_LEN) throw new Error(`UDP payload too large: ${payload.length}`);
        const resolved = await resolveTarget(target);
        const socket = resolved.family === 6 ? this.udp6 : this.udp4;
        if (!socket) throw new Error(`UDP IPv${resolved.family} is unavailable on this host`);
        stats.udpBytesOut += payload.length;
        stats.udpPacketsOut++;
        await new Promise((resolve, reject) => {
            socket.send(payload, target.port, resolved.address, (err) => (err ? reject(err) : resolve()));
        });
    }
    _onMessage(msg, rinfo) {
        const sink = this.sink;
        if (!sink || this.closed) return;
        stats.udpBytesIn += msg.length;
        stats.udpPacketsIn++;
        try {
            Promise.resolve(sink.mux.sendUDPData(sink.id, rinfo, Buffer.from(msg))).catch(() => {
            });
        } catch (err) {
            logEvent('warn', `dropped a UDP reply: ${err.message || err}`);
        }
    }
    close() {
        if (this.closed) return;
        this.closed = true;
        this.sink = null;
        activeUdpAssociations.delete(this);
        if (this.udp4) { try { this.udp4.close(); } catch {} }
        if (this.udp6) { try { this.udp6.close(); } catch {} }
        this.udp4 = null;
        this.udp6 = null;
    }
}

class XUDPManager {
    constructor(graceMs) {
        this.graceMs = graceMs;
        this.entries = new Map();
    }
    async attach(globalID, mux, sessionID) {
        const key = Buffer.from(globalID).toString('hex');
        let entry = this.entries.get(key);
        if (!entry) {
            entry = { assoc: await UDPAssociation.create(), timer: null };
            this.entries.set(key, entry);
        }
        if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
        const oldSink = entry.assoc.attach({ mux, id: sessionID });
        return { assoc: entry.assoc, oldSink };
    }
    detach(globalID, mux, sessionID) {
        const key = Buffer.from(globalID).toString('hex');
        const entry = this.entries.get(key);
        if (!entry || !entry.assoc.detach(mux, sessionID)) return;
        if (entry.timer) clearTimeout(entry.timer);
        entry.timer = setTimeout(() => {
            const current = this.entries.get(key);
            if (current !== entry) return;
            this.entries.delete(key);
            entry.assoc.close();
        }, this.graceMs);
        entry.timer.unref?.();
    }
    close() {
        for (const entry of this.entries.values()) {
            if (entry.timer) clearTimeout(entry.timer);
            entry.assoc.close();
        }
        this.entries.clear();
    }
    get size() { return this.entries.size; }
}

async function serveDirectUDP(socket, reader, target, conn) {
    if (rejectUdpTarget(target)) {
        logEvent('warn', `connection #${conn.id}: UDP/443 target rejected (${target.host}:443)`);
        await writeControlError(socket, 'UDP/443 rejected');
        return;
    }
    const assoc = await UDPAssociation.create();
    let closed = false;
    assoc.attach({
        mux: {
            sendUDPData: async (_id, _rinfo, data) => {
                if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return;
                const frame = Buffer.allocUnsafe(2 + data.length);
                frame.writeUInt16BE(data.length, 0);
                data.copy(frame, 2);
                await writeSocket(socket, frame, conn);
            },
        },
        id: 0,
    });
    try {
        await writeSocket(socket, Buffer.from([0]), conn);
        for (;;) {
            const payload = await readLengthPayload(reader);
            if (payload.length === 0) continue;
            if (rejectUdpTarget(target)) continue;
            await assoc.send(target, payload);
        }
    } finally {
        closed = true;
        assoc.close();
    }
}

async function readMuxFrame(reader) {
    const metaLen = (await reader.readExactly(2)).readUInt16BE(0);
    if (metaLen < 4 || metaLen > MAX_MUX_META_LEN) throw new Error(`invalid mux metadata length ${metaLen}`);
    const meta = await reader.readExactly(metaLen);
    const frame = { id: meta.readUInt16BE(0), status: meta[2], option: meta[3], network: 0, target: null, globalID: null, data: Buffer.alloc(0) };
    let cursor = 4;
    if (frame.status === MUX_STATUS_NEW) {
        if (cursor >= meta.length) throw new Error('mux New missing network');
        frame.network = meta[cursor++];
        const parsed = parseEndpointBytes(meta, cursor);
        frame.target = parsed.endpoint;
        cursor = parsed.next;
        if (frame.network === MUX_NETWORK_UDP && meta.length - cursor >= 8) {
            const gid = meta.subarray(cursor, cursor + 8);
            if (!gid.equals(Buffer.alloc(8))) frame.globalID = Buffer.from(gid);
            cursor += 8;
        }
        if (cursor !== meta.length) throw new Error(`unexpected ${meta.length - cursor} byte(s) in mux New metadata`);
    } else if (frame.status === MUX_STATUS_KEEP && meta.length > cursor && meta[cursor] === MUX_NETWORK_UDP) {
        frame.network = meta[cursor++];
        frame.target = parseEndpointBytes(meta, cursor).endpoint;
    }
    if ((frame.option & MUX_OPTION_DATA) !== 0) frame.data = await readLengthPayload(reader);
    return frame;
}

class MuxSession {
    constructor(mux, id, network, target) {
        this.mux = mux;
        this.id = id;
        this.network = network;
        this.target = target;
        this.udp = null;
        this.global = false;
        this.gid = null;
        this.closed = false;
    }
    async sendUDP(target, payload) {
        if (!this.udp) throw new Error('UDP session is unavailable');
        await this.udp.send(target, payload);
    }
    closeWithoutRemoving() {
        if (this.closed) return;
        this.closed = true;
        if (this.udp) {
            if (this.global) this.mux.xm.detach(this.gid, this.mux, this.id);
            else { this.udp.detach(this.mux, this.id); this.udp.close(); }
            this.udp = null;
        }
    }
    async close(sendEnd) {
        if (this.mux.sessions.get(this.id) === this) this.mux.sessions.delete(this.id);
        this.closeWithoutRemoving();
        if (sendEnd) await this.mux.sendEnd(this.id, true).catch(() => {});
    }
}

class MuxConnection {
    constructor(socket, reader, xm, conn) {
        this.socket = socket;
        this.reader = reader;
        this.xm = xm;
        this.conn = conn;
        this.sessions = new Map();
        this.closed = false;
        this.writeChain = Promise.resolve();
    }
    async serve() {
        try {
            await writeSocket(this.socket, Buffer.from([0]), this.conn);
            for (;;) {
                const frame = await readMuxFrame(this.reader);
                await this.handleFrame(frame);
            }
        } finally {
            this.closeAll();
        }
    }
    async handleFrame(frame) {
        if (frame.status === MUX_STATUS_KEEPALIVE) return;
        if (frame.status === MUX_STATUS_NEW) return this.handleNew(frame);
        if (frame.status === MUX_STATUS_KEEP) return this.handleKeep(frame);
        if (frame.status === MUX_STATUS_END) {
            const session = this.sessions.get(frame.id);
            if (session && frame.data.length) await session.sendUDP(session.target, frame.data).catch(() => {});
            this.removeSession(frame.id);
            return;
        }
        throw new Error(`unknown mux status 0x${frame.status.toString(16).padStart(2, '0')}`);
    }
    async handleNew(frame) {
        if (frame.network !== MUX_NETWORK_UDP || !frame.target?.host || !frame.target?.port || rejectUdpTarget(frame.target)) {
            if (frame.network === MUX_NETWORK_UDP && rejectUdpTarget(frame.target)) {
                logEvent('warn', `connection #${this.conn.id}: UDP/443 target rejected (${frame.target.host}:443)`);
            }
            await this.sendEnd(frame.id, true).catch(() => {});
            return;
        }
        this.removeSession(frame.id);
        const session = new MuxSession(this, frame.id, frame.network, frame.target);
        if (frame.globalID) {
            try {
                const { assoc, oldSink } = await this.xm.attach(frame.globalID, this, frame.id);
                session.udp = assoc;
                session.global = true;
                session.gid = Buffer.from(frame.globalID);
                this.sessions.set(session.id, session);
                if (oldSink && (oldSink.mux !== this || oldSink.id !== frame.id)) {
                    oldSink.mux.removeSession(oldSink.id);
                    await oldSink.mux.sendEnd(oldSink.id, false).catch(() => {});
                }
            } catch {
                await this.sendEnd(frame.id, true).catch(() => {});
                return;
            }
        } else {
            try {
                const assoc = await UDPAssociation.create();
                assoc.attach({ mux: this, id: frame.id });
                session.udp = assoc;
                this.sessions.set(session.id, session);
            } catch {
                await this.sendEnd(frame.id, true).catch(() => {});
                return;
            }
        }
        if (frame.data.length) await session.sendUDP(frame.target, frame.data).catch(() => session.close(true));
    }
    async handleKeep(frame) {
        const session = this.sessions.get(frame.id);
        if (!session) { await this.sendEnd(frame.id, false).catch(() => {}); return; }
        if (!frame.data.length) return;
        let target = session.target;
        if (frame.network === MUX_NETWORK_UDP && frame.target?.host && frame.target?.port) {
            target = frame.target;
            session.target = target;
        }
        if (rejectUdpTarget(target)) { logEvent('warn', `connection #${this.conn.id}: UDP/443 target rejected (${target.host}:443)`); await session.close(true); return; }
        await session.sendUDP(target, frame.data).catch(() => session.close(true));
    }
    removeSession(id) {
        const session = this.sessions.get(id);
        if (!session) return;
        this.sessions.delete(id);
        session.closeWithoutRemoving();
    }
    closeAll() {
        if (this.closed) return;
        this.closed = true;
        const sessions = [...this.sessions.values()];
        this.sessions.clear();
        for (const session of sessions) session.closeWithoutRemoving();
    }
    _queueWrite(data) {
        const op = this.writeChain.then(() => writeSocket(this.socket, data, this.conn));
        this.writeChain = op.catch(() => {});
        return op;
    }
    sendUDPData(id, source, data) {
        const addr = encodeUDPSource(source);
        const meta = Buffer.allocUnsafe(5 + addr.length);
        meta.writeUInt16BE(id, 0);
        meta[2] = MUX_STATUS_KEEP;
        meta[3] = MUX_OPTION_DATA;
        meta[4] = MUX_NETWORK_UDP;
        addr.copy(meta, 5);
        return this.writeMuxPacket(meta, data);
    }
    sendEnd(id, hasError) {
        const meta = Buffer.alloc(4);
        meta.writeUInt16BE(id, 0);
        meta[2] = MUX_STATUS_END;
        meta[3] = hasError ? MUX_OPTION_ERROR : 0;
        return this.writeMuxMeta(meta);
    }
    writeMuxPacket(meta, data) {
        if (data.length > MAX_PACKET_LEN) return Promise.reject(new Error(`mux payload too large: ${data.length}`));
        const out = Buffer.allocUnsafe(2 + meta.length + 2 + data.length);
        out.writeUInt16BE(meta.length, 0);
        meta.copy(out, 2);
        const off = 2 + meta.length;
        out.writeUInt16BE(data.length, off);
        data.copy(out, off + 2);
        return this._queueWrite(out);
    }
    writeMuxMeta(meta) {
        const out = Buffer.allocUnsafe(2 + meta.length);
        out.writeUInt16BE(meta.length, 0);
        meta.copy(out, 2);
        return this._queueWrite(out);
    }
}

function fmtDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    const s = ms / 1000;
    if (s < 60) return `${s.toFixed(1)}s`;
    return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
}

function isNormalClose(err) {
    if (!err) return true;
    const code = err.code || '';
    if (['EOF', 'ECONNRESET', 'EPIPE', 'ERR_STREAM_PREMATURE_CLOSE'].includes(code)) return true;
    const msg = String(err.message || err).toLowerCase();
    return msg.includes('unexpected eof') || msg.includes('socket is closed') || msg.includes('idle timeout');
}

async function handleRelayConnection(socket, cfg, xm) {
    const remote = `${socket.remoteAddress || '?'}:${socket.remotePort || '?'}`;
    const conn = { id: nextConnId++, openedAt: Date.now(), bytesIn: 0, bytesOut: 0 }; 
    stats.activeConnections++;
    const reader = new AsyncByteReader(socket, (n) => { conn.bytesIn += n; });
    let established = false;
    socket.setNoDelay(true);
    const onHandshakeTimeout = () => socket.destroy(new Error('handshake timeout'));
    socket.setTimeout(cfg.handshakeTimeout, onHandshakeTimeout);
    try {
        const control = await readControl(reader);
        established = true;
        socket.off('timeout', onHandshakeTimeout);
        socket.setTimeout(cfg.idleTimeout > 0 ? cfg.idleTimeout : 0, () => socket.destroy(new Error('idle timeout')));
        if (control.mode === RELAY_MODE_FIXED_UDP) {
            logEvent('info', `connection from ${remote}: fixed-UDP -> ${control.target.host}:${control.target.port}`, 'open');
            await serveDirectUDP(socket, reader, control.target, conn);
        } else {
            logEvent('info', `connection from ${remote}: mux (xudp)`, 'open');
            const mux = new MuxConnection(socket, reader, xm, conn);
            await mux.serve();
        }
    } catch (err) {
        if (!established && !socket.destroyed) {
            logEvent('warn', `connection from ${remote}: rejected (${err.message || err})`);
            await writeControlError(socket, 'malformed control header');
        } else if (!isNormalClose(err)) {
            logEvent('error', `connection from ${remote}: error - ${err.message || err}`);
        }
    } finally {
        socket.destroy();
        stats.activeConnections--;
        if (established) logEvent('info', `connection from ${remote}: closed after ${fmtDuration(Date.now() - conn.openedAt)}`, 'close');
    }
}

function statsSnapshot() {
    return {
        activeUdpConnections: activeUdpAssociations.size,
        udpBytesSent: stats.udpBytesOut,
        udpBytesReceived: stats.udpBytesIn,
        udpPacketsSent: stats.udpPacketsOut,
        udpPacketsReceived: stats.udpPacketsIn,
    };
}

function dashboardRequestHandler(req, res) {
    let url;
    try {
        url = new URL(req.url, 'http://localhost');
    } catch {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad Request');
        return;
    }
    if (url.pathname === '/api/stats') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(statsSnapshot()));
        return;
    }
    if (url.pathname === '/api/logs') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(logRing.slice(-200)));
        return;
    }
    if (url.pathname === '/api/logs/stream') {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-store',
            'Connection': 'keep-alive',
        });
        res.write(': connected\n\n');
        const send = (entry) => { res.write(`data: ${JSON.stringify(entry)}\n\n`); };
        logSubscribers.add(send);
        const keepAlive = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 20000);
        req.on('close', () => { clearInterval(keepAlive); logSubscribers.delete(send); });
        return;
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(DASHBOARD_HTML);
        return;
    }
    if (url.pathname === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
}

const DASHBOARD_HTML = String.raw`<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0c1628">
<meta name="color-scheme" content="dark">
<title>UDP Relay Monitor</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0a111f;
    --card: #101a2d;
    --line: #1d2a44;
    --ink: #e7ecf8;
    --dim: #8d99b3;
    --faint: #66738f;
    --sans: Roboto, system-ui, -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    --mono: "Roboto Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html { background: var(--bg); }
  body {
    margin: 0;
    min-height: 100vh;
    color: var(--ink);
    font-family: var(--sans);
    -webkit-text-size-adjust: 100%;
    background: linear-gradient(180deg, #132445 0, #0d1830 260px, var(--bg) 620px) no-repeat, var(--bg);
  }
  .wrap { max-width: 560px; margin: 0 auto; padding: 18px 16px 40px; }

  .tile { display: grid; place-items: center; flex: none; width: 56px; height: 56px; border-radius: 18px; }
  .blue { background: #1c3a6e; color: #9fc3ff; }
  .slate { background: #2a3352; color: #c9d2ec; }
  .purple { background: #3b2a5b; color: #d3b6fb; }
  .green { background: #153a2c; color: #6ee7a3; }
  .amber { background: #3a3118; color: #f0c674; }
  .red { background: #3e1f27; color: #f4a3a3; }

  header { display: flex; align-items: center; gap: 14px; padding: 6px 0 20px; }
  header .tile { width: 50px; height: 50px; border-radius: 16px; }
  h1 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }
  .live {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 7px 14px 7px 12px;
    border-radius: 999px;
    background: #16223a;
    color: var(--dim);
    font-size: 14px;
  }
  .live::before { content: ""; width: 10px; height: 10px; border-radius: 50%; background: var(--faint); }
  .live.on { color: #aab6d0; }
  .live.on::before { background: #6ee7a3; animation: pulse 2.4s infinite; }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(110, 231, 163, .45); }
    70%, 100% { box-shadow: 0 0 0 7px rgba(110, 231, 163, 0); }
  }
  @media (prefers-reduced-motion: reduce) { .live.on::before { animation: none; } }

  .card { background: var(--card); border: 1px solid var(--line); border-radius: 26px; }
  .stats { display: grid; gap: 14px; }
  .stat { display: flex; align-items: center; gap: 18px; padding: 18px 20px; }
  .lbl { font-size: 14px; color: var(--dim); }
  .val { font-size: 30px; font-weight: 700; line-height: 1.15; font-variant-numeric: tabular-nums; }
  .sub { font-size: 13px; color: var(--dim); font-variant-numeric: tabular-nums; }

  h2 { display: flex; align-items: center; gap: 10px; margin: 28px 4px 12px; font-size: 18px; font-weight: 600; }
  h2 svg { color: #9fc3ff; }
  .log { max-height: min(58vh, 480px); overflow-y: auto; padding: 4px 14px; overscroll-behavior: contain; }
  .ln { display: flex; align-items: center; gap: 14px; padding: 12px 0; border-bottom: 1px solid var(--line); }
  .ln:last-child { border-bottom: 0; }
  .ln .tile { width: 40px; height: 40px; border-radius: 50%; }
  .ln p { flex: 1; min-width: 0; margin: 0; font: 13px/1.55 var(--mono); overflow-wrap: anywhere; }
  .ln time { flex: none; font-size: 12px; color: var(--dim); white-space: nowrap; font-variant-numeric: tabular-nums; }
  .empty { padding: 22px 4px; color: var(--faint); font-size: 14px; }

  @media (min-width: 860px) {
    .wrap { max-width: 920px; }
    .stats { grid-template-columns: repeat(3, 1fr); }
    .log { max-height: min(60vh, 520px); }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="tile blue" aria-hidden="true">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19.1 4.9a10 10 0 0 1 0 14.2M4.9 19.1a10 10 0 0 1 0-14.2"/></svg>
    </div>
    <h1>UDP Relay Monitor</h1>
    <span class="live" id="live">Offline</span>
  </header>

  <section class="stats">
    <article class="card stat">
      <div class="tile blue" aria-hidden="true"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div>
      <div><div class="lbl">UDP Aktif</div><div class="val" id="v-conn">0</div></div>
    </article>
    <article class="card stat">
      <div class="tile slate" aria-hidden="true"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg></div>
      <div><div class="lbl">UDP Sent</div><div class="val" id="v-sent">0 B</div><div class="sub" id="p-sent">0 packets</div></div>
    </article>
    <article class="card stat">
      <div class="tile purple" aria-hidden="true"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M19 12l-7 7-7-7"/></svg></div>
      <div><div class="lbl">UDP Received</div><div class="val" id="v-recv">0 B</div><div class="sub" id="p-recv">0 packets</div></div>
    </article>
  </section>

  <h2><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 17l6-6-6-6M12 19h8"/></svg>Live log</h2>
  <section class="card log" id="log" role="log"><div class="empty" id="empty">Menunggu koneksi masuk…</div></section>
</div>

<script>
var MAX_ROWS = 200;
var $ = function (id) { return document.getElementById(id); };
function svg(p) {
  return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + p + '</svg>';
}
var ICON = {
  open: ['green', svg('<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/>')],
  close: ['slate', svg('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>')],
  warn: ['amber', svg('<path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>')],
  error: ['red', svg('<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>')],
  info: ['slate', svg('<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>')]
};

function fmtBytes(n) {
  if (n < 1024) return Math.round(n) + ' B';
  var u = ['KB', 'MB', 'GB', 'TB'], i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n < 100 ? n.toFixed(1) : String(Math.round(n))) + ' ' + u[i];
}
function fmtPackets(n) {
  return Number(n).toLocaleString('en-US') + (n === 1 ? ' packet' : ' packets');
}
function refreshStats() {
  return fetch('/api/stats', { cache: 'no-store' }).then(function (r) {
    return r.ok ? r.json() : null;
  }).then(function (s) {
    if (!s) return;
    $('v-conn').textContent = s.activeUdpConnections;
    $('v-sent').textContent = fmtBytes(s.udpBytesSent);
    $('p-sent').textContent = fmtPackets(s.udpPacketsSent || 0);
    $('v-recv').textContent = fmtBytes(s.udpBytesReceived);
    $('p-recv').textContent = fmtPackets(s.udpPacketsReceived || 0);
  }).catch(function () {});
}

var logEl = $('log');
var seen = {};
var rows = 0;
function addLog(e) {
  if (seen[e.id]) return;
  seen[e.id] = true;
  delete seen[e.id - 1000];
  var empty = $('empty');
  if (empty) empty.remove();
  var k = ICON[e.kind] || ICON[e.level] || ICON.info;
  var row = document.createElement('div');
  row.className = 'ln';
  row.dataset.id = e.id;
  row.innerHTML = '<div class="tile ' + k[0] + '" aria-hidden="true">' + k[1] + '</div><p></p><time></time>';
  row.querySelector('p').textContent = e.message;
  row.querySelector('time').textContent = new Date(e.ts).toLocaleTimeString('en-US');
  var ref = logEl.firstChild;
  while (ref && Number(ref.dataset.id) > e.id) ref = ref.nextSibling;
  logEl.insertBefore(row, ref);
  if (++rows > MAX_ROWS) { logEl.removeChild(logEl.lastChild); rows--; }
}
function resetLog() {
  seen = {};
  rows = 0;
  logEl.innerHTML = '<div class="empty" id="empty">Menunggu koneksi masuk…</div>';
}
function loadHistory() {
  return fetch('/api/logs', { cache: 'no-store' }).then(function (r) {
    return r.ok ? r.json() : [];
  }).then(function (arr) { arr.forEach(addLog); }).catch(function () {});
}

var liveEl = $('live');
function setLive(on) {
  liveEl.textContent = on ? 'Live' : 'Offline';
  liveEl.className = on ? 'live on' : 'live';
}
function connectStream() {
  var es = new EventSource('/api/logs/stream');
  es.onopen = function () { setLive(true); resetLog(); loadHistory(); };
  es.onmessage = function (ev) { addLog(JSON.parse(ev.data)); };
  es.onerror = function () { setLive(false); };
}

refreshStats();
setInterval(refreshStats, 2000);
connectStream();
</script>
</body>
</html>
`;

function buildConfig() {
    return {
        listenAddress: { host: CONFIG.LISTEN_HOST, port: CONFIG.LISTEN_PORT },
        handshakeTimeout: CONFIG.HANDSHAKE_TIMEOUT_MS,
        idleTimeout: CONFIG.IDLE_TIMEOUT_MS,
        xudpGrace: CONFIG.XUDP_GRACE_MS,
        maxConns: CONFIG.MAX_CONNECTIONS,
    };
}

function createServer(cfg = buildConfig()) {
    const xm = new XUDPManager(cfg.xudpGrace);
    const httpServer = http.createServer(dashboardRequestHandler);
    httpServer.keepAliveTimeout = 60000;

    const tcpServer = net.createServer((socket) => {
        if (stats.activeConnections >= cfg.maxConns) {
            socket.end();
            return;
        }
        const onHandshakeTimeout = () => socket.destroy();
        socket.setTimeout(cfg.handshakeTimeout, onHandshakeTimeout);
        socket.once('error', () => {}); 
        socket.once('data', (firstChunk) => {
            socket.pause();
            socket.off('timeout', onHandshakeTimeout);
            socket.setTimeout(0);
            const isRelay = firstChunk.length >= RELAY_MAGIC.length && firstChunk.subarray(0, RELAY_MAGIC.length).equals(RELAY_MAGIC);
            socket.unshift(firstChunk);
            if (isRelay) {
                handleRelayConnection(socket, cfg, xm).catch((err) => {
                    logEvent('error', `relay connection handler crashed: ${err?.stack || err}`);
                    socket.destroy();
                });
            } else {
                httpServer.emit('connection', socket);
            }
            socket.resume();
        });
    });
    tcpServer.on('close', () => xm.close());
    return { tcpServer, httpServer, xm, cfg };
}

async function start(overrides = {}) {
    const cfg = { ...buildConfig(), ...overrides };
    const { tcpServer } = createServer(cfg);
    await new Promise((resolve, reject) => {
        tcpServer.once('error', reject);
        tcpServer.listen(cfg.listenAddress.port, cfg.listenAddress.host, () => {
            tcpServer.off('error', reject);
            resolve();
        });
    });
    return { tcpServer, cfg };
}

async function main() {
    const { tcpServer } = await start();
    const addr = tcpServer.address();
    logEvent('info', `udprelay listening on ${addr.address}:${addr.port}`);
    const shutdown = () => {
        logEvent('info', 'shutting down');
        tcpServer.close(() => process.exit(0));
        setTimeout(() => process.exit(1), 5000).unref();
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
}

if (require.main === module) {
    main().catch((err) => {
        console.error(err?.stack || err);
        process.exitCode = 1;
    });
}

module.exports = {
    CONFIG, RELAY_MAGIC, RELAY_MODE_FIXED_UDP, RELAY_MODE_MUX,
    createServer, start, buildConfig,
    AsyncByteReader, readMuxFrame, encodeUDPSource,
};
