"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const { EventEmitter } = require("events");

const DEFAULT_MAX_HEADER_BYTES = 16 * 1024;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_HOVER_TIMEOUT_MS = 5000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 1500;
const DEFAULT_EXIT_GRACE_MS = 500;
const DEFAULT_KILL_GRACE_MS = 500;

function isExecutableFile(filePath, isWin, fsMod) {
    try {
        const st = fsMod.statSync(filePath);
        if (!st || !st.isFile()) {
            return false;
        }
        if (!isWin) {
            const xOk = fsMod.constants && typeof fsMod.constants.X_OK === "number"
                ? fsMod.constants.X_OK
                : 1;
            fsMod.accessSync(filePath, xOk);
        }
        return true;
    } catch (_) {
        return false;
    }
}

function expandTilde(inputPath, homedir, pathMod) {
    if (inputPath === "~") {
        return homedir || inputPath;
    }
    if (inputPath.startsWith("~/") || inputPath.startsWith("~\\")) {
        return homedir ? pathMod.join(homedir, inputPath.slice(2)) : inputPath;
    }
    return inputPath;
}

function normalizeWorkspacePath(entry) {
    if (typeof entry === "string") {
        return entry;
    }
    if (entry && entry.uri && typeof entry.uri.fsPath === "string") {
        return entry.uri.fsPath;
    }
    return null;
}

function getPathEntries(env, isWin) {
    const rawPath = (env && (env.PATH || env.Path)) || "";
    if (!rawPath) {
        return [];
    }
    const sep = isWin ? ";" : ":";
    return String(rawPath)
        .split(sep)
        .map((part) => part.trim().replace(/^"+|"+$/g, ""))
        .filter((part) => part.length > 0);
}

function resolveNinoBinary(opts = {}) {
    const platform = opts.platform || process.platform;
    const isWin = platform === "win32";
    const pathMod = isWin ? path.win32 : path.posix;
    const fsMod = opts.fs || fs;
    const env = opts.env || process.env;
    const homedir = opts.homedir !== undefined ? opts.homedir : os.homedir();
    const workspaceRoots = Array.isArray(opts.workspacePaths)
        ? opts.workspacePaths.map(normalizeWorkspacePath).filter(Boolean)
        : [];
    const cwd = opts.cwd || workspaceRoots[0] || process.cwd();
    const logger = typeof opts.logger === "function" ? opts.logger : null;

    const exeName = (base) => (isWin && !base.toLowerCase().endsWith(".exe") ? base + ".exe" : base);
    const checked = [];

    const tryCandidate = (candidatePath, source) => {
        checked.push(candidatePath);
        if (isExecutableFile(candidatePath, isWin, fsMod)) {
            if (logger) {
                logger("info", `Resolved Nino LSP server (${source}): ${candidatePath}`);
            }
            return { command: candidatePath, source, checked };
        }
        return null;
    };

    const rawConfigured = opts.compilerPath !== undefined ? opts.compilerPath : opts.configuredPath;
    if (typeof rawConfigured === "string" && rawConfigured.trim().length > 0) {
        const trimmed = rawConfigured.trim();
        const expanded = expandTilde(trimmed, homedir, pathMod);
        const hasSeparator = expanded.includes("/") || expanded.includes("\\") || pathMod.isAbsolute(expanded);

        if (hasSeparator) {
            const baseDir = workspaceRoots[0] || cwd;
            const resolved = pathMod.isAbsolute(expanded) ? expanded : pathMod.resolve(baseDir, expanded);
            const candidates = (isWin && !resolved.toLowerCase().endsWith(".exe"))
                ? [resolved + ".exe", resolved]
                : [resolved];
            for (const candidate of candidates) {
                const hit = tryCandidate(candidate, "compilerPath");
                if (hit) {
                    return hit;
                }
            }
        } else {
            const pathEntries = getPathEntries(env, isWin);
            const names = (isWin && !trimmed.toLowerCase().endsWith(".exe"))
                ? [trimmed + ".exe", trimmed]
                : [trimmed];
            for (const dir of pathEntries) {
                for (const name of names) {
                    const hit = tryCandidate(pathMod.join(dir, name), "compilerPath");
                    if (hit) {
                        return hit;
                    }
                }
            }
        }

        const errMsg = `Configured nino.compilerPath was not found or is not executable: ${trimmed}`;
        if (logger) {
            logger("error", errMsg);
        }
        return { command: null, source: null, checked, error: errMsg };
    }

    for (const root of workspaceRoots) {
        const candidates = [
            pathMod.join(root, exeName("ninoc")),
            pathMod.join(root, "bin", exeName("ninoc")),
            pathMod.join(root, "compiler", exeName("ninoc")),
            pathMod.join(root, exeName("nino")),
            pathMod.join(root, "bin", exeName("nino"))
        ];
        for (const candidate of candidates) {
            const hit = tryCandidate(candidate, "workspace");
            if (hit) {
                return hit;
            }
        }
    }

    const ninoHome = env && typeof env.NINO_HOME === "string" ? env.NINO_HOME.trim() : "";
    if (ninoHome) {
        const candidates = [
            pathMod.join(ninoHome, "bin", exeName("ninoc")),
            pathMod.join(ninoHome, "bin", exeName("nino")),
            pathMod.join(ninoHome, exeName("ninoc")),
            pathMod.join(ninoHome, exeName("nino"))
        ];
        for (const candidate of candidates) {
            const hit = tryCandidate(candidate, "NINO_HOME");
            if (hit) {
                return hit;
            }
        }
    }

    const pathEntries = getPathEntries(env, isWin);
    for (const binName of [exeName("ninoc"), exeName("nino")]) {
        for (const dir of pathEntries) {
            const hit = tryCandidate(pathMod.join(dir, binName), "PATH");
            if (hit) {
                return hit;
            }
        }
    }

    if (homedir) {
        const homeBin = pathMod.join(homedir, ".nino", "bin");
        for (const binName of [exeName("ninoc"), exeName("nino")]) {
            const hit = tryCandidate(pathMod.join(homeBin, binName), "home");
            if (hit) {
                return hit;
            }
        }
    }

    const errMsg = "Nino compiler binary (ninoc or nino) not found. Checked nino.compilerPath, workspace folders, NINO_HOME, PATH, and ~/.nino/bin.";
    if (logger) {
        logger("error", errMsg);
    }
    return { command: null, source: null, checked, error: errMsg };
}

function encodeLspMessage(message) {
    const json = JSON.stringify(message);
    const body = Buffer.from(json, "utf8");
    const header = Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "ascii");
    return Buffer.concat([header, body]);
}

class LspMessageReader extends EventEmitter {
    constructor(options = {}) {
        super();
        this.buffer = Buffer.alloc(0);
        this.expectedLength = null;
        this.skipBytesRemaining = 0;
        this.maxHeaderBytes = typeof options.maxHeaderBytes === "number"
            ? options.maxHeaderBytes
            : DEFAULT_MAX_HEADER_BYTES;
        this.maxBodyBytes = typeof options.maxBodyBytes === "number"
            ? options.maxBodyBytes
            : DEFAULT_MAX_BODY_BYTES;
        this.onMessage = typeof options.onMessage === "function" ? options.onMessage : null;
        this.onWarning = typeof options.onWarning === "function" ? options.onWarning : null;
        this.onError = typeof options.onError === "function" ? options.onError : null;
    }

    _emitWarning(message) {
        if (this.onWarning) {
            this.onWarning(message);
        }
        this.emit("warning", message);
    }

    _emitError(err) {
        if (this.onError) {
            this.onError(err);
        }
        if (this.listenerCount("error") > 0) {
            this.emit("error", err);
        }
    }

    _emitMessage(msg) {
        if (this.onMessage) {
            this.onMessage(msg);
        }
        this.emit("message", msg);
    }

    reset() {
        this.buffer = Buffer.alloc(0);
        this.expectedLength = null;
        this.skipBytesRemaining = 0;
    }

    push(chunk) {
        if (chunk === undefined || chunk === null || chunk.length === 0) {
            return;
        }
        let buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (this.skipBytesRemaining > 0 && this.buffer.length === 0) {
            if (buf.length <= this.skipBytesRemaining) {
                this.skipBytesRemaining -= buf.length;
                return;
            }
            buf = buf.subarray(this.skipBytesRemaining);
            this.skipBytesRemaining = 0;
        }
        this.buffer = this.buffer.length === 0 ? buf : Buffer.concat([this.buffer, buf]);

        while (this.buffer.length > 0) {
            if (this.skipBytesRemaining > 0) {
                if (this.buffer.length <= this.skipBytesRemaining) {
                    this.skipBytesRemaining -= this.buffer.length;
                    this.buffer = Buffer.alloc(0);
                    break;
                }
                const afterSkip = this.buffer.subarray(this.skipBytesRemaining);
                this.buffer = afterSkip.length === 0 ? Buffer.alloc(0) : afterSkip;
                this.skipBytesRemaining = 0;
                continue;
            }

            if (this.expectedLength === null) {
                const crlfIdx = this.buffer.indexOf("\r\n\r\n");
                const lfIdx = this.buffer.indexOf("\n\n");
                let headerEnd = -1;
                let sepLen = 0;

                if (crlfIdx !== -1 && (lfIdx === -1 || crlfIdx < lfIdx)) {
                    headerEnd = crlfIdx;
                    sepLen = 4;
                } else if (lfIdx !== -1) {
                    headerEnd = lfIdx;
                    sepLen = 2;
                }

                if (headerEnd === -1) {
                    if (this.buffer.length > this.maxHeaderBytes) {
                        this.buffer = Buffer.alloc(0);
                        this._emitError(new Error(`LSP header exceeded maximum size (${this.maxHeaderBytes} bytes); discarded buffer`));
                    }
                    break;
                }

                if (headerEnd > this.maxHeaderBytes) {
                    this.buffer = this.buffer.subarray(headerEnd + sepLen);
                    if (this.buffer.length === 0) {
                        this.buffer = Buffer.alloc(0);
                    }
                    this._emitError(new Error(`LSP header block exceeded maximum size (${this.maxHeaderBytes} bytes); resynchronizing`));
                    continue;
                }

                const headerStr = this.buffer.subarray(0, headerEnd).toString("latin1");
                const restAfterHeader = this.buffer.subarray(headerEnd + sepLen);
                this.buffer = restAfterHeader.length === 0 ? Buffer.alloc(0) : restAfterHeader;

                const lines = headerStr.split(/\r?\n/);
                let parsedLength = null;
                let oversizedLength = null;
                let invalidLength = false;

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) {
                        continue;
                    }
                    const clMatch = /^content-length\s*:\s*(\d+)\s*$/i.exec(trimmed);
                    if (clMatch) {
                        const n = Number(clMatch[1]);
                        if (!Number.isSafeInteger(n) || n < 0) {
                            invalidLength = true;
                        } else if (n > this.maxBodyBytes) {
                            if (oversizedLength !== null && oversizedLength !== n) {
                                invalidLength = true;
                            } else if (parsedLength !== null && parsedLength !== n) {
                                invalidLength = true;
                            } else {
                                oversizedLength = n;
                            }
                        } else if (parsedLength !== null && parsedLength !== n) {
                            invalidLength = true;
                        } else if (oversizedLength !== null && oversizedLength !== n) {
                            invalidLength = true;
                        } else {
                            parsedLength = n;
                        }
                        continue;
                    }
                    if (/^content-length\s*:/i.test(trimmed)) {
                        invalidLength = true;
                        continue;
                    }
                    if (!/^[a-z0-9-]+\s*:/i.test(trimmed)) {
                        this._emitWarning(`Ignoring non-header line before LSP frame: ${trimmed}`);
                    }
                }

                if (invalidLength) {
                    this.expectedLength = null;
                    this._emitError(new Error(`Malformed or missing Content-Length header in block: ${JSON.stringify(headerStr)}`));
                    continue;
                }

                if (oversizedLength !== null) {
                    this.expectedLength = null;
                    this.skipBytesRemaining = oversizedLength;
                    this._emitError(new Error(`LSP message Content-Length (${oversizedLength} bytes) exceeds maximum allowed body size (${this.maxBodyBytes} bytes); discarding body`));
                    continue;
                }

                if (parsedLength === null) {
                    this.expectedLength = null;
                    this._emitError(new Error(`Malformed or missing Content-Length header in block: ${JSON.stringify(headerStr)}`));
                    continue;
                }

                this.expectedLength = parsedLength;
            }

            if (this.buffer.length < this.expectedLength) {
                break;
            }

            const bodyLen = this.expectedLength;
            const bodyBuf = this.buffer.subarray(0, bodyLen);
            const rest = this.buffer.subarray(bodyLen);
            this.buffer = rest.length === 0 ? Buffer.alloc(0) : rest;
            this.expectedLength = null;

            let msg;
            try {
                msg = JSON.parse(bodyBuf.toString("utf8"));
            } catch (err) {
                this._emitError(new Error(`Invalid JSON-RPC payload (${bodyLen} bytes): ${err.message}`));
                continue;
            }

            this._emitMessage(msg);
        }
    }
}

function makeCancelledError(message = "Request cancelled") {
    const err = new Error(message);
    err.code = "REQUEST_CANCELLED";
    return err;
}

class LspJsonRpcConnection extends EventEmitter {
    constructor(proc, options = {}) {
        super();
        if (!proc || !proc.stdin || !proc.stdout) {
            throw new Error("LspJsonRpcConnection requires a process with stdin and stdout streams");
        }
        this.proc = proc;
        this.nextId = 1;
        this.pendingRequests = new Map();
        this.traceLevel = LspJsonRpcConnection.normalizeTraceLevel(options.traceLevel);
        this.logger = typeof options.logger === "function" ? options.logger : null;
        this.closed = false;
        this._stderrRemainder = "";

        this.reader = new LspMessageReader({
            maxHeaderBytes: options.maxHeaderBytes,
            maxBodyBytes: options.maxBodyBytes,
            onMessage: (msg) => this._handleMessage(msg),
            onWarning: (warn) => this._log("warn", warn),
            onError: (err) => this._log("error", `LSP stream parse error: ${err.message}`)
        });

        this._onStdoutData = (chunk) => {
            this.reader.push(chunk);
        };
        this._onStdinError = (err) => {
            this._log("warn", `LSP stdin error (${err.code || "ERR"}): ${err.message}`);
        };
        this._onStderrData = (chunk) => {
            const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
            const combined = this._stderrRemainder + text;
            const parts = combined.split(/\r?\n/);
            this._stderrRemainder = parts.pop() || "";
            for (const line of parts) {
                this._emitStderrLine(line);
            }
        };
        this._onStderrEnd = () => {
            if (this._stderrRemainder.length > 0) {
                const line = this._stderrRemainder;
                this._stderrRemainder = "";
                this._emitStderrLine(line);
            }
        };
        this._onProcError = (err) => {
            this._log("error", `Language server process error: ${err.message}`);
            this.rejectAllPending(err);
            this.emit("processError", err);
            if (this.listenerCount("error") > 0) {
                this.emit("error", err);
            }
        };
        this._onProcExit = (code, signal) => {
            this._onStderrEnd();
            this.closed = true;
            const err = new Error(`Language server exited (code=${code}, signal=${signal})`);
            err.code = "SERVER_EXITED";
            this.rejectAllPending(err);
            this.emit("exit", { code, signal });
        };

        proc.stdout.on("data", this._onStdoutData);
        proc.stdin.on("error", this._onStdinError);
        if (proc.stderr) {
            proc.stderr.on("data", this._onStderrData);
            proc.stderr.on("end", this._onStderrEnd);
        }
        if (typeof proc.on === "function") {
            proc.on("error", this._onProcError);
            proc.on("exit", this._onProcExit);
        }
    }

    static normalizeTraceLevel(level) {
        if (level === "messages" || level === "verbose") {
            return level;
        }
        return "off";
    }

    setTraceLevel(level) {
        this.traceLevel = LspJsonRpcConnection.normalizeTraceLevel(level);
    }

    _log(level, message) {
        if (this.logger) {
            this.logger(level, message);
        }
    }

    _trace(direction, summary, payload) {
        if (this.traceLevel === "off") {
            return;
        }
        const ts = new Date().toISOString();
        this._log("trace", `[Trace - ${ts}] ${direction} ${summary}`);
        if (this.traceLevel === "verbose" && payload !== undefined) {
            try {
                this._log("trace", JSON.stringify(payload));
            } catch (_) {
                this._log("trace", String(payload));
            }
        }
    }

    _emitStderrLine(line) {
        this._log("stderr", `[stderr] ${line}`);
        this.emit("stderr", line);
    }

    _writeMessage(payload) {
        if (this.closed || !this.proc.stdin || this.proc.stdin.destroyed || !this.proc.stdin.writable) {
            return false;
        }
        try {
            const frame = encodeLspMessage(payload);
            this.proc.stdin.write(frame);
            return true;
        } catch (err) {
            this._log("warn", `Failed writing LSP frame: ${err.message}`);
            return false;
        }
    }

    sendNotification(method, params) {
        const msg = { jsonrpc: "2.0", method };
        if (params !== undefined) {
            msg.params = params;
        }
        this._trace("Sending notification", `'${method}'`, params);
        return this._writeMessage(msg);
    }

    sendRequest(method, params, options = {}) {
        if (this.closed) {
            return Promise.reject(new Error("Cannot send request on closed LSP connection"));
        }

        const token = options.cancellationToken || null;
        const signal = options.signal || null;

        if ((token && token.isCancellationRequested) || (signal && signal.aborted)) {
            return Promise.reject(makeCancelledError());
        }

        const id = this.nextId++;
        const timeoutMs = typeof options.timeoutMs === "number"
            ? options.timeoutMs
            : DEFAULT_REQUEST_TIMEOUT_MS;
        const msg = { jsonrpc: "2.0", id, method };
        if (params !== undefined) {
            msg.params = params;
        }

        this._trace("Sending request", `'${method} - (${id})'`, params);

        return new Promise((resolve, reject) => {
            let cancelDisposable = null;
            let abortListener = null;

            const cleanup = () => {
                if (entry.timer) {
                    clearTimeout(entry.timer);
                    entry.timer = null;
                }
                if (cancelDisposable && typeof cancelDisposable.dispose === "function") {
                    try {
                        cancelDisposable.dispose();
                    } catch (_) {}
                    cancelDisposable = null;
                }
                if (signal && abortListener && typeof signal.removeEventListener === "function") {
                    signal.removeEventListener("abort", abortListener);
                    abortListener = null;
                }
            };

            const entry = {
                id,
                method,
                startTime: Date.now(),
                timer: null,
                resolve: (val) => {
                    cleanup();
                    resolve(val);
                },
                reject: (err) => {
                    cleanup();
                    reject(err);
                }
            };

            if (timeoutMs > 0) {
                entry.timer = setTimeout(() => {
                    if (!this.pendingRequests.has(id)) {
                        return;
                    }
                    this.pendingRequests.delete(id);
                    const err = new Error(`LSP request '${method}' (${id}) timed out after ${timeoutMs}ms`);
                    err.code = "REQUEST_TIMEOUT";
                    entry.reject(err);
                }, timeoutMs);
            }

            const onCancel = () => {
                if (!this.pendingRequests.has(id)) {
                    return;
                }
                this.pendingRequests.delete(id);
                this.sendNotification("$/cancelRequest", { id });
                entry.reject(makeCancelledError());
            };

            if (token && typeof token.onCancellationRequested === "function") {
                cancelDisposable = token.onCancellationRequested(onCancel);
            }
            if (signal && typeof signal.addEventListener === "function") {
                abortListener = onCancel;
                signal.addEventListener("abort", abortListener, { once: true });
            }

            this.pendingRequests.set(id, entry);

            if (!this._writeMessage(msg)) {
                if (this.pendingRequests.delete(id)) {
                    entry.reject(new Error(`Failed to write LSP request '${method}' (${id}) to stdin`));
                }
            }
        });
    }

    _handleMessage(msg) {
        if (!msg || typeof msg !== "object") {
            return;
        }

        const hasId = Object.prototype.hasOwnProperty.call(msg, "id") && msg.id !== undefined && msg.id !== null;
        const hasMethod = typeof msg.method === "string";

        if (hasId && !hasMethod) {
            const entry = this.pendingRequests.get(msg.id);
            if (!entry) {
                this._trace("Received response (ignored)", `(${msg.id})`, msg);
                return;
            }
            this.pendingRequests.delete(msg.id);
            const elapsed = Date.now() - entry.startTime;
            this._trace("Received response", `'${entry.method} - (${msg.id})' (${elapsed}ms)`, msg.error || msg.result);

            if (msg.error) {
                const err = new Error(msg.error.message || `JSON-RPC error ${msg.error.code}`);
                err.code = msg.error.code;
                err.data = msg.error.data;
                entry.reject(err);
            } else {
                entry.resolve(msg.result !== undefined ? msg.result : null);
            }
            return;
        }

        if (hasMethod) {
            if (hasId) {
                this._trace("Received server request", `'${msg.method} - (${msg.id})'`, msg.params);
                this._writeMessage({
                    jsonrpc: "2.0",
                    id: msg.id,
                    error: {
                        code: -32601,
                        message: `Method not implemented on client: ${msg.method}`
                    }
                });
                return;
            }

            this._trace("Received notification", `'${msg.method}'`, msg.params);
            this.emit("notification", { method: msg.method, params: msg.params });
            if (msg.method === "textDocument/publishDiagnostics") {
                this.emit("publishDiagnostics", msg.params);
            }
        }
    }

    rejectAllPending(err, exceptId) {
        for (const [id, entry] of Array.from(this.pendingRequests.entries())) {
            if (exceptId !== undefined && id === exceptId) {
                continue;
            }
            this.pendingRequests.delete(id);
            entry.reject(err);
        }
    }

    dispose() {
        this.closed = true;
        this.rejectAllPending(new Error("LSP connection disposed"));
        if (this.proc.stdout && typeof this.proc.stdout.removeListener === "function") {
            this.proc.stdout.removeListener("data", this._onStdoutData);
        }
        if (this.proc.stdin && typeof this.proc.stdin.removeListener === "function") {
            this.proc.stdin.removeListener("error", this._onStdinError);
        }
        if (this.proc.stderr && typeof this.proc.stderr.removeListener === "function") {
            this.proc.stderr.removeListener("data", this._onStderrData);
            this.proc.stderr.removeListener("end", this._onStderrEnd);
        }
        if (typeof this.proc.removeListener === "function") {
            this.proc.removeListener("error", this._onProcError);
            this.proc.removeListener("exit", this._onProcExit);
        }
        this.reader.reset();
    }
}

class NinoLspClient extends EventEmitter {
    constructor(options = {}) {
        super();
        this.options = options;
        this.command = options.command || null;
        this.args = Array.isArray(options.args) ? options.args.slice() : ["lsp"];
        this.spawnFn = typeof options.spawn === "function" ? options.spawn : spawn;
        this.logger = typeof options.logger === "function" ? options.logger : null;
        this.traceLevel = LspJsonRpcConnection.normalizeTraceLevel(options.traceLevel);
        this.requestTimeoutMs = typeof options.requestTimeoutMs === "number"
            ? options.requestTimeoutMs
            : DEFAULT_REQUEST_TIMEOUT_MS;
        this.hoverTimeoutMs = typeof options.hoverTimeoutMs === "number"
            ? options.hoverTimeoutMs
            : DEFAULT_HOVER_TIMEOUT_MS;
        this.shutdownTimeoutMs = typeof options.shutdownTimeoutMs === "number"
            ? options.shutdownTimeoutMs
            : DEFAULT_SHUTDOWN_TIMEOUT_MS;
        this.exitGraceMs = typeof options.exitGraceMs === "number"
            ? options.exitGraceMs
            : DEFAULT_EXIT_GRACE_MS;
        this.killGraceMs = typeof options.killGraceMs === "number"
            ? options.killGraceMs
            : DEFAULT_KILL_GRACE_MS;

        this.state = "idle";
        this.proc = null;
        this.connection = null;
        this.serverCapabilities = {};
        this.serverInfo = null;
        this.openDocs = new Map();
        this.readyPromise = null;
        this._stopPromise = null;
        this.resolvedInfo = null;
    }

    _log(level, message) {
        if (this.logger) {
            this.logger(level, message);
        }
    }

    setTraceLevel(level) {
        this.traceLevel = LspJsonRpcConnection.normalizeTraceLevel(level);
        if (this.connection) {
            this.connection.setTraceLevel(this.traceLevel);
        }
    }

    getOpenVersion(uri) {
        return this.openDocs.has(uri) ? this.openDocs.get(uri) : null;
    }

    isDocumentOpen(uri) {
        return this.openDocs.has(uri);
    }

    async start() {
        if (this.state === "ready") {
            return { capabilities: this.serverCapabilities, serverInfo: this.serverInfo };
        }
        if (this.state === "starting" && this.readyPromise) {
            return this.readyPromise;
        }
        if (this.state !== "idle") {
            throw new Error(`Cannot start NinoLspClient from state '${this.state}'`);
        }

        let command = this.command;
        if (!command) {
            const resolution = resolveNinoBinary({
                compilerPath: this.options.compilerPath,
                workspacePaths: this.options.workspacePaths,
                env: this.options.env,
                platform: this.options.platform,
                homedir: this.options.homedir,
                cwd: this.options.cwd,
                fs: this.options.fs,
                logger: this.logger
            });
            this.resolvedInfo = resolution;
            if (!resolution.command) {
                this.state = "failed";
                throw new Error(resolution.error || "Unable to locate ninoc or nino executable");
            }
            command = resolution.command;
            this.command = command;
        }

        this.state = "starting";

        const startRun = (async () => {
            const cwd = this.options.cwd
                || (Array.isArray(this.options.workspacePaths) && normalizeWorkspacePath(this.options.workspacePaths[0]))
                || path.dirname(command);

            let proc;
            try {
                proc = this.spawnFn(command, this.args, {
                    cwd,
                    env: this.options.env || process.env,
                    stdio: ["pipe", "pipe", "pipe"],
                    windowsHide: true,
                    shell: false
                });
            } catch (err) {
                if (this.state !== "stopping" && this.state !== "stopped") {
                    this.state = "failed";
                }
                this._log("error", `Failed to spawn '${command}': ${err.message}`);
                throw err;
            }

            this.proc = proc;
            const connection = new LspJsonRpcConnection(proc, {
                traceLevel: this.traceLevel,
                logger: this.logger,
                maxHeaderBytes: this.options.maxHeaderBytes,
                maxBodyBytes: this.options.maxBodyBytes
            });
            this.connection = connection;

            connection.on("publishDiagnostics", (params) => {
                this.emit("publishDiagnostics", params);
            });
            connection.on("notification", (evt) => {
                this.emit("notification", evt);
            });
            connection.on("stderr", (line) => {
                this.emit("stderr", line);
            });
            connection.on("processError", (err) => {
                if (this.state !== "stopping" && this.state !== "stopped") {
                    this.state = "failed";
                }
                this.emit("serverError", err);
            });
            connection.on("exit", ({ code, signal }) => {
                const expected = this.state === "stopping" || this.state === "stopped";
                if (!expected) {
                    this.state = "failed";
                    this._log("error", `Nino LSP server exited unexpectedly (code=${code}, signal=${signal})`);
                }
                this.openDocs.clear();
                this.emit("exit", { code, signal, expected });
            });

            const initParams = {
                processId: process.pid,
                clientInfo: this.options.clientInfo || {
                    name: "nino-vscode",
                    version: "1.0.0"
                },
                rootUri: this.options.rootUri !== undefined ? this.options.rootUri : null,
                workspaceFolders: this.options.workspaceFolders !== undefined ? this.options.workspaceFolders : null,
                capabilities: {
                    workspace: {
                        workspaceFolders: true
                    },
                    textDocument: {
                        synchronization: {
                            dynamicRegistration: false,
                            willSave: false,
                            willSaveWaitUntil: false,
                            didSave: false
                        },
                        hover: {
                            dynamicRegistration: false,
                            contentFormat: ["markdown", "plaintext"]
                        },
                        publishDiagnostics: {
                            relatedInformation: false,
                            versionSupport: true
                        }
                    }
                }
            };

            const result = await connection.sendRequest("initialize", initParams, {
                timeoutMs: this.requestTimeoutMs
            });

            if (this.state !== "starting") {
                throw new Error(`Client state changed to '${this.state}' during initialize`);
            }

            this.serverCapabilities = (result && result.capabilities) || {};
            this.serverInfo = (result && result.serverInfo) || null;
            connection.sendNotification("initialized", {});
            this.state = "ready";
            this.emit("ready", { capabilities: this.serverCapabilities, serverInfo: this.serverInfo });
            return { capabilities: this.serverCapabilities, serverInfo: this.serverInfo };
        })();

        this.readyPromise = startRun;

        try {
            return await startRun;
        } catch (err) {
            const isStoppingOrStopped = this.state === "stopping" || this.state === "stopped";
            if (!isStoppingOrStopped) {
                this.state = "failed";
                if (this.proc && this.proc.exitCode === null && this.proc.signalCode === null) {
                    try {
                        this.proc.kill();
                    } catch (_) {}
                }
            }
            throw err;
        }
    }

    async _ensureReadyForSync() {
        if (this.state === "ready") {
            return true;
        }
        if (this.state === "starting" && this.readyPromise) {
            try {
                await this.readyPromise;
                return this.state === "ready";
            } catch (_) {
                return false;
            }
        }
        return false;
    }

    async didOpen(uri, text, version = 1, languageId = "nino") {
        if (!(await this._ensureReadyForSync())) {
            return false;
        }
        if (this.openDocs.has(uri)) {
            return false;
        }
        const ver = Number.isInteger(version) ? version : 1;
        this.openDocs.set(uri, ver);
        return this.connection.sendNotification("textDocument/didOpen", {
            textDocument: {
                uri,
                languageId,
                version: ver,
                text: String(text)
            }
        });
    }

    async didChange(uri, text, version) {
        if (!(await this._ensureReadyForSync())) {
            return false;
        }
        if (!this.openDocs.has(uri)) {
            return this.didOpen(uri, text, version);
        }
        const prev = this.openDocs.get(uri) || 0;
        const next = Number.isInteger(version) && version > prev ? version : prev + 1;
        this.openDocs.set(uri, next);
        return this.connection.sendNotification("textDocument/didChange", {
            textDocument: {
                uri,
                version: next
            },
            contentChanges: [{ text: String(text) }]
        });
    }

    didClose(uri) {
        if (!this.openDocs.has(uri)) {
            return false;
        }
        this.openDocs.delete(uri);
        if (this.state !== "ready" || !this.connection) {
            return false;
        }
        return this.connection.sendNotification("textDocument/didClose", {
            textDocument: { uri }
        });
    }

    async hover(uri, line, character, options = {}) {
        if (this.state !== "ready" || !this.connection) {
            return null;
        }
        if (this.serverCapabilities && this.serverCapabilities.hoverProvider === false) {
            return null;
        }
        const token = options.token || options.cancellationToken || null;
        if (token && token.isCancellationRequested) {
            return null;
        }
        try {
            return await this.connection.sendRequest(
                "textDocument/hover",
                {
                    textDocument: { uri },
                    position: {
                        line: Math.max(0, Number(line) || 0),
                        character: Math.max(0, Number(character) || 0)
                    }
                },
                {
                    timeoutMs: typeof options.timeoutMs === "number" ? options.timeoutMs : this.hoverTimeoutMs,
                    cancellationToken: token,
                    signal: options.signal
                }
            );
        } catch (err) {
            if (err && err.code !== "REQUEST_CANCELLED") {
                this._log("warn", `Hover request failed: ${err.message}`);
            }
            return null;
        }
    }

    stop() {
        if (this._stopPromise) {
            return this._stopPromise;
        }

        if (this.state === "idle" || this.state === "stopped") {
            this.state = "stopped";
            this.openDocs.clear();
            this._stopPromise = Promise.resolve();
            return this._stopPromise;
        }

        this.state = "stopping";
        const proc = this.proc;
        const connection = this.connection;

        this._stopPromise = (async () => {
            try {
                if (connection && proc && proc.exitCode === null && proc.signalCode === null) {
                    connection.rejectAllPending(new Error("Language client stopping"));
                    try {
                        await connection.sendRequest("shutdown", null, {
                            timeoutMs: this.shutdownTimeoutMs
                        });
                    } catch (_) {}
                    try {
                        connection.sendNotification("exit", null);
                    } catch (_) {}
                }

                if (proc && proc.stdin && !proc.stdin.destroyed) {
                    try {
                        proc.stdin.end();
                    } catch (_) {}
                }

                if (proc && proc.exitCode === null && proc.signalCode === null) {
                    const exitedGracefully = await this._waitForExit(proc, this.exitGraceMs);
                    if (!exitedGracefully && proc.exitCode === null && proc.signalCode === null) {
                        try {
                            proc.kill("SIGTERM");
                        } catch (_) {}
                        const exitedAfterTerm = await this._waitForExit(proc, this.killGraceMs);
                        if (!exitedAfterTerm && proc.exitCode === null && proc.signalCode === null) {
                            try {
                                proc.kill("SIGKILL");
                            } catch (_) {}
                            await this._waitForExit(proc, 200);
                        }
                    }
                }
            } finally {
                if (connection) {
                    connection.dispose();
                }
                this.openDocs.clear();
                this.state = "stopped";
                this.emit("stopped");
            }
        })();

        return this._stopPromise;
    }

    _waitForExit(proc, timeoutMs) {
        if (!proc || proc.exitCode !== null || proc.signalCode !== null) {
            return Promise.resolve(true);
        }
        return new Promise((resolve) => {
            let done = false;
            let timer = null;
            const finish = (exited) => {
                if (done) {
                    return;
                }
                done = true;
                if (timer) {
                    clearTimeout(timer);
                    timer = null;
                }
                if (typeof proc.removeListener === "function") {
                    proc.removeListener("exit", onExit);
                }
                resolve(exited);
            };
            const onExit = () => finish(true);
            if (typeof proc.once === "function") {
                proc.once("exit", onExit);
            } else if (typeof proc.on === "function") {
                proc.on("exit", onExit);
            }
            timer = setTimeout(() => finish(proc.exitCode !== null || proc.signalCode !== null), timeoutMs);
        });
    }
}

module.exports = {
    DEFAULT_MAX_HEADER_BYTES,
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_REQUEST_TIMEOUT_MS,
    DEFAULT_HOVER_TIMEOUT_MS,
    DEFAULT_SHUTDOWN_TIMEOUT_MS,
    resolveNinoBinary,
    encodeLspMessage,
    LspMessageReader,
    LspJsonRpcConnection,
    NinoLspClient
};
