"use strict";

const lspClient = require("./lsp-client");

const VIRTUAL_SCHEMES = new Set([
    "output",
    "debug",
    "git",
    "vscode-scm",
    "comment",
    "vscode-userdata"
]);

function getVscode(override) {
    if (override) {
        return override;
    }
    return require("vscode");
}

function isNinoDocument(doc) {
    if (!doc || doc.languageId !== "nino" || !doc.uri) {
        return false;
    }
    const scheme = typeof doc.uri.scheme === "string" ? doc.uri.scheme : "file";
    return !VIRTUAL_SCHEMES.has(scheme);
}

function clampNonNegativeInt(value) {
    const n = Number(value);
    if (!Number.isFinite(n) || n < 0) {
        return 0;
    }
    return Math.floor(n);
}

function toVscodeRange(vscodeApi, lspRange) {
    const startLine = clampNonNegativeInt(lspRange && lspRange.start && lspRange.start.line);
    const startChar = clampNonNegativeInt(lspRange && lspRange.start && lspRange.start.character);
    const endLine = clampNonNegativeInt(lspRange && lspRange.end && lspRange.end.line);
    const endChar = clampNonNegativeInt(lspRange && lspRange.end && lspRange.end.character);

    if (typeof vscodeApi.Position === "function") {
        return new vscodeApi.Range(
            new vscodeApi.Position(startLine, startChar),
            new vscodeApi.Position(endLine, endChar)
        );
    }
    return new vscodeApi.Range(startLine, startChar, endLine, endChar);
}

function mapDiagnosticSeverity(vscodeApi, severity) {
    const sev = vscodeApi.DiagnosticSeverity || {
        Error: 0,
        Warning: 1,
        Information: 2,
        Hint: 3
    };
    switch (severity) {
        case 1:
            return sev.Error;
        case 2:
            return sev.Warning;
        case 3:
            return sev.Information;
        case 4:
            return sev.Hint;
        default:
            return sev.Error;
    }
}

function normalizeUriComparable(uriString) {
    if (typeof uriString !== "string") {
        return "";
    }
    try {
        return decodeURIComponent(uriString).toLowerCase();
    } catch (_) {
        return uriString.toLowerCase();
    }
}

function findMatchingOpenDocument(vscodeApi, uriString) {
    const docs = (vscodeApi.workspace && Array.isArray(vscodeApi.workspace.textDocuments))
        ? vscodeApi.workspace.textDocuments
        : [];
    if (docs.length === 0) {
        return null;
    }

    for (const doc of docs) {
        if (doc && doc.uri && doc.uri.toString() === uriString) {
            return doc;
        }
    }

    let parsedString = uriString;
    if (vscodeApi.Uri && typeof vscodeApi.Uri.parse === "function") {
        try {
            parsedString = vscodeApi.Uri.parse(uriString).toString();
        } catch (_) {}
    }

    for (const doc of docs) {
        if (doc && doc.uri && doc.uri.toString() === parsedString) {
            return doc;
        }
    }

    const targetNorm = normalizeUriComparable(parsedString);
    for (const doc of docs) {
        if (doc && doc.uri && normalizeUriComparable(doc.uri.toString()) === targetNorm) {
            return doc;
        }
    }

    return null;
}

function convertHoverItem(vscodeApi, item) {
    if (item === null || item === undefined) {
        return null;
    }
    if (typeof item === "string") {
        if (item.length === 0) {
            return null;
        }
        return new vscodeApi.MarkdownString(item);
    }
    if (typeof item === "object") {
        if (typeof item.kind === "string") {
            const val = typeof item.value === "string" ? item.value : "";
            if (val.length === 0) {
                return null;
            }
            if (item.kind === "plaintext") {
                const md = new vscodeApi.MarkdownString();
                if (typeof md.appendText === "function") {
                    md.appendText(val);
                } else {
                    md.value = val;
                }
                return md;
            }
            return new vscodeApi.MarkdownString(val);
        }
        if (typeof item.language === "string" && typeof item.value === "string") {
            if (item.value.length === 0) {
                return null;
            }
            const md = new vscodeApi.MarkdownString();
            if (typeof md.appendCodeblock === "function") {
                md.appendCodeblock(item.value, item.language);
            } else {
                md.value = "```" + item.language + "\n" + item.value + "\n```";
            }
            return md;
        }
        if (typeof item.value === "string" && item.value.length > 0) {
            return new vscodeApi.MarkdownString(item.value);
        }
    }
    return null;
}

function convertHoverResult(vscodeApi, lspHover) {
    if (!lspHover || lspHover.contents === undefined || lspHover.contents === null) {
        return null;
    }

    let contents;
    if (Array.isArray(lspHover.contents)) {
        const mapped = lspHover.contents
            .map((entry) => convertHoverItem(vscodeApi, entry))
            .filter(Boolean);
        if (mapped.length === 0) {
            return null;
        }
        contents = mapped;
    } else {
        const single = convertHoverItem(vscodeApi, lspHover.contents);
        if (!single) {
            return null;
        }
        contents = single;
    }

    const range = lspHover.range ? toVscodeRange(vscodeApi, lspHover.range) : undefined;
    return range !== undefined
        ? new vscodeApi.Hover(contents, range)
        : new vscodeApi.Hover(contents);
}

function createExtension(vscodeOverride, deps = {}) {
    const vscodeApi = getVscode(vscodeOverride || deps.vscode);
    const outputChannel = vscodeApi.window.createOutputChannel("Nino Language Server");
    const diagnosticCollection = vscodeApi.languages.createDiagnosticCollection("nino");

    const logger = (level, message) => {
        const prefix = level === "trace" || level === "stderr" ? "" : `[${level}] `;
        outputChannel.appendLine(`${prefix}${message}`);
    };

    let client = null;
    let disposed = false;
    let reportedErrorKey = null;
    let startPromise = null;
    let stopPromise = null;
    let restartChain = Promise.resolve(true);

    const reportErrorOnce = (key, message) => {
        if (reportedErrorKey === key) {
            return;
        }
        reportedErrorKey = key;
        if (vscodeApi.window && typeof vscodeApi.window.showErrorMessage === "function") {
            Promise.resolve(vscodeApi.window.showErrorMessage(message)).catch(() => {});
        }
    };

    const getConfig = () => {
        if (vscodeApi.workspace && typeof vscodeApi.workspace.getConfiguration === "function") {
            return vscodeApi.workspace.getConfiguration("nino");
        }
        return { get: (_k, def) => def };
    };

    const getWorkspaceInfo = () => {
        const folders = (vscodeApi.workspace && Array.isArray(vscodeApi.workspace.workspaceFolders))
            ? vscodeApi.workspace.workspaceFolders
            : [];
        if (folders.length === 0) {
            return {
                workspacePaths: [],
                rootUri: null,
                workspaceFolders: null
            };
        }
        return {
            workspacePaths: folders.map((f) => f.uri && f.uri.fsPath).filter(Boolean),
            rootUri: folders[0].uri.toString(),
            workspaceFolders: folders.map((f) => ({
                uri: f.uri.toString(),
                name: f.name || ""
            }))
        };
    };

    const handlePublishDiagnostics = (params) => {
        if (!params || typeof params.uri !== "string" || !Array.isArray(params.diagnostics)) {
            return;
        }
        const matchedDoc = findMatchingOpenDocument(vscodeApi, params.uri);
        const targetUri = matchedDoc
            ? matchedDoc.uri
            : vscodeApi.Uri.parse(params.uri);

        if (typeof params.version === "number") {
            const openVer = matchedDoc && typeof matchedDoc.version === "number"
                ? matchedDoc.version
                : (client ? client.getOpenVersion(params.uri) : null);
            if (typeof openVer === "number" && params.version < openVer) {
                return;
            }
        }

        const mapped = params.diagnostics.map((d) => {
            const range = toVscodeRange(vscodeApi, d && d.range);
            const severity = mapDiagnosticSeverity(vscodeApi, d && d.severity);
            const message = d && d.message !== undefined ? String(d.message) : "";
            const diag = new vscodeApi.Diagnostic(range, message, severity);
            diag.source = (d && d.source) || "nino";
            if (d && d.code !== undefined && d.code !== null) {
                diag.code = d.code;
            }
            return diag;
        });

        diagnosticCollection.set(targetUri, mapped);
    };

    const syncOpenDocuments = async (activeClient) => {
        const docs = (vscodeApi.workspace && Array.isArray(vscodeApi.workspace.textDocuments))
            ? vscodeApi.workspace.textDocuments
            : [];
        for (const doc of docs) {
            if (disposed || activeClient !== client) {
                return;
            }
            if (!isNinoDocument(doc)) {
                continue;
            }
            await activeClient.didOpen(
                doc.uri.toString(),
                doc.getText(),
                doc.version,
                doc.languageId
            );
        }
    };

    const start = async () => {
        if (disposed) {
            return false;
        }
        if (startPromise) {
            return startPromise;
        }

        const currentStart = (async () => {
            stopPromise = null;
            const cfg = getConfig();
            const compilerPath = cfg.get("compilerPath", "");
            const traceLevel = cfg.get("trace.server", "off");
            const wsInfo = getWorkspaceInfo();
            const timeouts = deps.timeouts || {};

            const newClient = new lspClient.NinoLspClient({
                compilerPath,
                workspacePaths: wsInfo.workspacePaths,
                rootUri: wsInfo.rootUri,
                workspaceFolders: wsInfo.workspaceFolders,
                env: deps.env,
                platform: deps.platform,
                homedir: deps.homedir,
                cwd: deps.cwd,
                fs: deps.fs,
                spawn: deps.spawn,
                traceLevel,
                logger,
                requestTimeoutMs: timeouts.requestTimeoutMs,
                hoverTimeoutMs: timeouts.hoverTimeoutMs,
                shutdownTimeoutMs: timeouts.shutdownTimeoutMs,
                exitGraceMs: timeouts.exitGraceMs,
                killGraceMs: timeouts.killGraceMs
            });

            client = newClient;

            newClient.on("publishDiagnostics", handlePublishDiagnostics);
            newClient.on("serverError", (err) => {
                if (!disposed && client === newClient) {
                    reportErrorOnce(
                        `serverError:${err.message}`,
                        `Nino Language Server failed: ${err.message}`
                    );
                }
            });
            newClient.on("exit", ({ code, signal, expected }) => {
                if (!expected && !disposed && client === newClient) {
                    reportErrorOnce(
                        `exit:${code}:${signal}`,
                        `Nino Language Server exited unexpectedly (code=${code}, signal=${signal}). Use "Nino: Restart Language Server" to restart.`
                    );
                }
            });

            try {
                await newClient.start();
                if (disposed || client !== newClient) {
                    return false;
                }
                reportedErrorKey = null;
                logger("info", "Nino Language Server initialized.");
                await syncOpenDocuments(newClient);
                return !disposed && client === newClient;
            } catch (err) {
                logger("error", `Failed to start Nino Language Server: ${err.message}`);
                if (!disposed && client === newClient) {
                    reportErrorOnce(
                        `start:${err.message}`,
                        `Failed to start Nino Language Server: ${err.message}`
                    );
                }
                return false;
            }
        })();

        startPromise = currentStart;

        try {
            return await currentStart;
        } finally {
            if (startPromise === currentStart) {
                startPromise = null;
            }
        }
    };

    const stop = () => {
        if (stopPromise) {
            return stopPromise;
        }
        const targetClient = client;
        const pendingStart = startPromise;
        client = null;
        stopPromise = (async () => {
            if (targetClient) {
                await targetClient.stop();
            }
            if (pendingStart) {
                try {
                    await pendingStart;
                } catch (_) {}
            }
        })();
        return stopPromise;
    };

    const runRestart = async () => {
        if (disposed) {
            return false;
        }
        logger("info", "Restarting Nino Language Server...");
        await stop();
        if (disposed) {
            return false;
        }
        diagnosticCollection.clear();
        reportedErrorKey = null;
        return start();
    };

    const restart = () => {
        if (disposed) {
            return Promise.resolve(false);
        }
        const next = restartChain.then(runRestart, runRestart);
        restartChain = next.catch(() => false);
        return next;
    };

    const disposables = [outputChannel, diagnosticCollection];

    if (vscodeApi.workspace) {
        if (typeof vscodeApi.workspace.onDidOpenTextDocument === "function") {
            disposables.push(
                vscodeApi.workspace.onDidOpenTextDocument((doc) => {
                    if (!client || !isNinoDocument(doc)) {
                        return;
                    }
                    client.didOpen(doc.uri.toString(), doc.getText(), doc.version, doc.languageId).catch(() => {});
                })
            );
        }

        if (typeof vscodeApi.workspace.onDidChangeTextDocument === "function") {
            disposables.push(
                vscodeApi.workspace.onDidChangeTextDocument((event) => {
                    if (!client || !event || !Array.isArray(event.contentChanges) || event.contentChanges.length === 0) {
                        return;
                    }
                    const doc = event.document;
                    if (!isNinoDocument(doc)) {
                        return;
                    }
                    client.didChange(doc.uri.toString(), doc.getText(), doc.version).catch(() => {});
                })
            );
        }

        if (typeof vscodeApi.workspace.onDidCloseTextDocument === "function") {
            disposables.push(
                vscodeApi.workspace.onDidCloseTextDocument((doc) => {
                    if (!isNinoDocument(doc)) {
                        return;
                    }
                    const uriStr = doc.uri.toString();
                    if (client) {
                        client.didClose(uriStr);
                    }
                    diagnosticCollection.delete(doc.uri);
                })
            );
        }

        if (typeof vscodeApi.workspace.onDidChangeConfiguration === "function") {
            disposables.push(
                vscodeApi.workspace.onDidChangeConfiguration((event) => {
                    if (!event || typeof event.affectsConfiguration !== "function") {
                        return;
                    }
                    if (event.affectsConfiguration("nino.trace.server")) {
                        const traceLevel = getConfig().get("trace.server", "off");
                        if (client) {
                            client.setTraceLevel(traceLevel);
                        }
                        logger("info", `Updated nino.trace.server to '${traceLevel}'.`);
                    }
                    if (event.affectsConfiguration("nino.compilerPath")) {
                        restart().catch(() => {});
                    }
                })
            );
        }
    }

    if (vscodeApi.languages && typeof vscodeApi.languages.registerHoverProvider === "function") {
        disposables.push(
            vscodeApi.languages.registerHoverProvider("nino", {
                async provideHover(document, position, token) {
                    if (!client || client.state !== "ready" || !isNinoDocument(document)) {
                        return null;
                    }
                    if (token && token.isCancellationRequested) {
                        return null;
                    }
                    const result = await client.hover(
                        document.uri.toString(),
                        position.line,
                        position.character,
                        { token }
                    );
                    if (token && token.isCancellationRequested) {
                        return null;
                    }
                    return convertHoverResult(vscodeApi, result);
                }
            })
        );
    }

    if (vscodeApi.commands && typeof vscodeApi.commands.registerCommand === "function") {
        disposables.push(
            vscodeApi.commands.registerCommand("nino.restartServer", () => restart())
        );
    }

    const dispose = () => {
        disposed = true;
        const p = stop();
        for (const d of disposables) {
            if (d && typeof d.dispose === "function") {
                try {
                    d.dispose();
                } catch (_) {}
            }
        }
        return p;
    };

    return {
        start,
        stop,
        restart,
        dispose,
        disposables,
        outputChannel,
        diagnosticCollection,
        getClient: () => client
    };
}

let activeController = null;

async function activate(context, deps = {}) {
    const controller = createExtension(deps.vscode, deps);
    activeController = controller;

    if (context && Array.isArray(context.subscriptions)) {
        for (const d of controller.disposables) {
            context.subscriptions.push(d);
        }
        context.subscriptions.push({
            dispose: () => {
                if (activeController === controller) {
                    activeController = null;
                }
                return controller.dispose();
            }
        });
    }

    await controller.start();
    return controller;
}

function deactivate() {
    const controller = activeController;
    activeController = null;
    if (!controller) {
        return Promise.resolve();
    }
    return controller.stop();
}

module.exports = {
    activate,
    deactivate,
    createExtension,
    isNinoDocument,
    convertHoverResult,
    ...lspClient
};
