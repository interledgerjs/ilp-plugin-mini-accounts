"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const BtpPacket = require('btp-packet');
const WebSocket = require("ws");
const assert = require("assert");
const ilp_plugin_btp_1 = require("ilp-plugin-btp");
const ILDCP = require("ilp-protocol-ildcp");
const IlpPacket = require("ilp-packet");
const { Errors } = IlpPacket;
const StoreWrapper = require('ilp-store-wrapper');
const origin_whitelist_1 = require("./lib/origin-whitelist");
const token_1 = require("./token");
const createLogger = require('ilp-logger');
const DEBUG_NAMESPACE = 'ilp-plugin-mini-accounts';
function tokenToAccount(token) {
    return BtpPacket.base64url(crypto.createHash('sha256').update(token).digest());
}
var AccountMode;
(function (AccountMode) {
    AccountMode[AccountMode["Username"] = 0] = "Username";
    AccountMode[AccountMode["HashToken"] = 1] = "HashToken";
    AccountMode[AccountMode["UsernameOrHashToken"] = 2] = "UsernameOrHashToken";
})(AccountMode || (AccountMode = {}));
function accountModeIsStored(mode) {
    return mode === AccountMode.Username || mode === AccountMode.UsernameOrHashToken;
}
function noopTrace(...msg) { }
class Plugin extends ilp_plugin_btp_1.default {
    constructor(opts, { log, store } = {}) {
        super({});
        this._connections = new Map();
        if (opts.wsOpts && opts.wsOpts.port && opts.port) {
            throw new Error('Specify at most one of: `ops.wsOpts.port`, `opts.port`.');
        }
        else if (opts.wsOpts && opts.wsOpts.port) {
            this._port = opts.wsOpts.port;
        }
        else if (opts.port) {
            this._port = opts.port;
        }
        else {
            this._port = 3000;
        }
        this._wsOpts = opts.wsOpts || { port: this._port };
        if (this._wsOpts.server) {
            this._miniAccountsHttpServer = this._wsOpts.server;
        }
        this._currencyScale = opts.currencyScale || 9;
        this._debugHostIldcpInfo = opts.debugHostIldcpInfo;
        const _store = store || opts._store;
        this._accountMode = _store ? AccountMode.UsernameOrHashToken : AccountMode.HashToken;
        if (opts.generateAccount === true)
            this._accountMode = AccountMode.HashToken;
        if (opts.generateAccount === false) {
            if (!_store) {
                throw new Error('_store is required when generateAccount is false');
            }
            this._accountMode = AccountMode.Username;
        }
        this._log = log || createLogger(DEBUG_NAMESPACE);
        this._log.trace = this._log.trace || noopTrace;
        this._allowedOrigins = new origin_whitelist_1.default(opts.allowedOrigins || []);
        if (_store) {
            this._store = new StoreWrapper(_store);
        }
    }
    _preConnect() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    _connect(address, authPacket, opts) {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    _close(account, err) {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    _sendPrepare(destination, parsedPacket) { }
    ilpAddressToAccount(ilpAddress) {
        if (ilpAddress.substr(0, this._prefix.length) !== this._prefix) {
            throw new Error('ILP address (' + ilpAddress + ') must start with prefix (' + this._prefix + ')');
        }
        return ilpAddress.substr(this._prefix.length).split('.')[0];
    }
    connect() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._wss)
                return;
            if (this._debugHostIldcpInfo) {
                this._hostIldcpInfo = this._debugHostIldcpInfo;
            }
            else if (this._dataHandler) {
                this._hostIldcpInfo = yield ILDCP.fetch(this._dataHandler.bind(this));
            }
            else {
                throw new Error('no request handler registered');
            }
            this._prefix = this._hostIldcpInfo.clientAddress + '.';
            if (this._preConnect) {
                try {
                    yield this._preConnect();
                }
                catch (err) {
                    this._log.debug(`Error on _preConnect. Reason is: ${err.message}`);
                    throw new Error('Failed to connect');
                }
            }
            this._log.info('listening on port ' + this._port);
            if (this._miniAccountsHttpServer) {
                this._miniAccountsHttpServer.listen(this._port);
            }
            const wss = this._wss = new WebSocket.Server(this._wsOpts);
            wss.on('connection', (wsIncoming, req) => {
                this._log.trace('got connection');
                if (typeof req.headers.origin === 'string' && !this._allowedOrigins.isOk(req.headers.origin)) {
                    this._log.debug(`Closing a websocket connection received from a browser. Origin is ${req.headers.origin}`);
                    this._log.debug('If you are running moneyd, you may allow this origin with the flag --allow-origin.' +
                        ' Run moneyd --help for details.');
                    wsIncoming.close();
                    return;
                }
                let token;
                let account;
                const closeHandler = (error) => {
                    this._log.debug('incoming ws closed. error=', error);
                    if (account)
                        this._removeConnection(account, wsIncoming);
                    if (this._close) {
                        this._close(this._prefix + account, error)
                            .catch(e => {
                            this._log.debug('error during custom close handler. error=', e);
                        });
                    }
                };
                wsIncoming.on('close', closeHandler);
                wsIncoming.on('error', closeHandler);
                let authPacket;
                wsIncoming.once('message', (binaryAuthMessage) => __awaiter(this, void 0, void 0, function* () {
                    try {
                        authPacket = BtpPacket.deserialize(binaryAuthMessage);
                        assert.strictEqual(authPacket.type, BtpPacket.TYPE_MESSAGE, 'First message sent over BTP connection must be auth packet');
                        assert(authPacket.data.protocolData.length >= 2, 'Auth packet must have auth and auth_token subprotocols');
                        assert.strictEqual(authPacket.data.protocolData[0].protocolName, 'auth', 'First subprotocol must be auth');
                        for (let subProtocol of authPacket.data.protocolData) {
                            if (subProtocol.protocolName === 'auth_token') {
                                token = subProtocol.data.toString();
                            }
                            else if (subProtocol.protocolName === 'auth_username') {
                                account = subProtocol.data.toString();
                            }
                        }
                        assert(token, 'auth_token subprotocol is required');
                        switch (this._accountMode) {
                            case AccountMode.Username:
                                assert(account, 'auth_username subprotocol is required');
                                break;
                            case AccountMode.HashToken:
                                assert(!account || account === tokenToAccount(token), 'auth_username subprotocol is not available');
                                break;
                        }
                        if (!account)
                            account = tokenToAccount(token);
                        this._addConnection(account, wsIncoming);
                        this._log.trace('got auth info. token=' + token, 'account=' + account);
                        if (accountModeIsStored(this._accountMode) && this._store) {
                            const storedToken = yield token_1.default.load({ account, store: this._store });
                            const receivedToken = new token_1.default({ account, token, store: this._store });
                            if (storedToken) {
                                if (!storedToken.equal(receivedToken)) {
                                    throw new Error('incorrect token for account.' +
                                        ' account=' + account +
                                        ' token=' + token);
                                }
                            }
                            else {
                                receivedToken.save();
                            }
                        }
                        if (this._connect) {
                            yield this._connect(this._prefix + account, authPacket, {
                                ws: wsIncoming,
                                req
                            });
                        }
                        wsIncoming.send(BtpPacket.serializeResponse(authPacket.requestId, []));
                    }
                    catch (err) {
                        if (authPacket) {
                            this._log.debug('not accepted error during auth. error="%s" readyState=%d', err, wsIncoming.readyState);
                            const errorResponse = BtpPacket.serializeError({
                                code: 'F00',
                                name: 'NotAcceptedError',
                                data: err.message || err.name,
                                triggeredAt: new Date().toISOString()
                            }, authPacket.requestId, []);
                            if (wsIncoming.readyState === WebSocket.OPEN) {
                                wsIncoming.send(errorResponse);
                            }
                        }
                        wsIncoming.close();
                        return;
                    }
                    this._log.trace('connection authenticated');
                    wsIncoming.on('message', (binaryMessage) => __awaiter(this, void 0, void 0, function* () {
                        let btpPacket;
                        try {
                            btpPacket = BtpPacket.deserialize(binaryMessage);
                        }
                        catch (err) {
                            wsIncoming.close();
                            return;
                        }
                        this._log.trace('account %s: processing btp packet %o', account, btpPacket);
                        try {
                            this._log.trace('packet is authorized, forwarding to host');
                            yield this._handleIncomingBtpPacket(this._prefix + account, btpPacket);
                        }
                        catch (err) {
                            this._log.debug('btp packet not accepted. error="%s" readyState=%d', err, wsIncoming.readyState);
                            const errorResponse = BtpPacket.serializeError({
                                code: 'F00',
                                name: 'NotAcceptedError',
                                triggeredAt: new Date().toISOString(),
                                data: err.message
                            }, btpPacket.requestId, []);
                            if (wsIncoming.readyState === WebSocket.OPEN) {
                                wsIncoming.send(errorResponse);
                            }
                        }
                    }));
                }));
            });
        });
    }
    disconnect() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._disconnect) {
                yield this._disconnect();
            }
            if (this._wss) {
                const wss = this._wss;
                yield new Promise((resolve) => wss.close(resolve));
                this._connections.clear();
                if (this._miniAccountsHttpServer) {
                    yield new Promise((resolve) => {
                        this._miniAccountsHttpServer.close(resolve);
                    });
                }
                this._wss = null;
            }
        });
    }
    isConnected() {
        return !!this._wss;
    }
    sendData(buffer) {
        return __awaiter(this, void 0, void 0, function* () {
            const parsedPacket = IlpPacket.deserializeIlpPacket(buffer);
            if (parsedPacket.type !== IlpPacket.Type.TYPE_ILP_PREPARE) {
                throw new Error(`can't route packet that's not a PREPARE.`);
            }
            const { destination, expiresAt, executionCondition } = parsedPacket.data;
            if (this._sendPrepare) {
                this._sendPrepare(destination, parsedPacket);
            }
            if (destination === 'peer.config') {
                return ILDCP.serializeIldcpResponse(this._hostIldcpInfo);
            }
            if (!destination.startsWith(this._prefix)) {
                throw new Error(`can't route packet that is not meant for one of my clients. destination=${destination} prefix=${this._prefix}`);
            }
            let timeout;
            const duration = expiresAt.getTime() - Date.now();
            const timeoutPacket = () => IlpPacket.serializeIlpReject({
                code: 'R00',
                message: 'Packet expired',
                triggeredBy: this._hostIldcpInfo.clientAddress,
                data: Buffer.alloc(0)
            });
            const timeoutPromise = new Promise(resolve => {
                timeout = setTimeout(() => resolve(timeoutPacket()), duration);
            });
            const responsePromise = this._call(destination, {
                type: BtpPacket.TYPE_MESSAGE,
                requestId: crypto.randomBytes(4).readUInt32BE(0),
                data: {
                    protocolData: [{
                            protocolName: 'ilp',
                            contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
                            data: buffer
                        }]
                }
            }).then(response => response.protocolData.filter(p => p.protocolName === 'ilp')[0].data);
            const ilpResponse = yield Promise.race([
                timeoutPromise,
                responsePromise
            ]);
            clearTimeout(timeout);
            const parsedIlpResponse = IlpPacket.deserializeIlpPacket(ilpResponse);
            if (parsedIlpResponse.type === IlpPacket.Type.TYPE_ILP_FULFILL) {
                const isExpired = Date.now() > expiresAt.getTime();
                if (isExpired) {
                    return timeoutPacket();
                }
                const { fulfillment } = parsedIlpResponse.data;
                if (!crypto.createHash('sha256')
                    .update(fulfillment)
                    .digest()
                    .equals(executionCondition)) {
                    return IlpPacket.errorToReject(this._hostIldcpInfo.clientAddress, new Errors.WrongConditionError('condition and fulfillment don\'t match. ' +
                        `condition=${executionCondition.toString('hex')} ` +
                        `fulfillment=${fulfillment.toString('hex')}`));
                }
            }
            if (this._handlePrepareResponse) {
                try {
                    this._handlePrepareResponse(destination, parsedIlpResponse, parsedPacket);
                }
                catch (e) {
                    return IlpPacket.errorToReject(this._hostIldcpInfo.clientAddress, e);
                }
            }
            return ilpResponse || Buffer.alloc(0);
        });
    }
    _handleData(from, btpPacket) {
        return __awaiter(this, void 0, void 0, function* () {
            const { ilp } = this.protocolDataToIlpAndCustom(btpPacket.data);
            if (ilp) {
                const parsedPacket = IlpPacket.deserializeIlpPacket(ilp);
                if (parsedPacket.data['destination'] === 'peer.config') {
                    this._log.trace('responding to ILDCP request. clientAddress=%s', from);
                    return [{
                            protocolName: 'ilp',
                            contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
                            data: yield ILDCP.serve({
                                requestPacket: ilp,
                                handler: () => __awaiter(this, void 0, void 0, function* () {
                                    return (Object.assign({}, this._hostIldcpInfo, { clientAddress: from }));
                                }),
                                serverAddress: this._hostIldcpInfo.clientAddress
                            })
                        }];
                }
            }
            if (this._handleCustomData) {
                this._log.trace('passing non-ILDCP data to custom handler');
                return this._handleCustomData(from, btpPacket);
            }
            if (!ilp) {
                this._log.debug('invalid packet, no ilp protocol data. from=%s', from);
                throw new Error('invalid packet, no ilp protocol data.');
            }
            if (!this._dataHandler) {
                throw new Error('no request handler registered');
            }
            const response = yield this._dataHandler(ilp);
            return this.ilpAndCustomToProtocolData({ ilp: response });
        });
    }
    _handleOutgoingBtpPacket(to, btpPacket) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!to.startsWith(this._prefix)) {
                throw new Error(`invalid destination, must start with prefix. destination=${to} prefix=${this._prefix}`);
            }
            const account = this.ilpAddressToAccount(to);
            const connections = this._connections.get(account);
            if (!connections) {
                throw new Error('No clients connected for account ' + account);
            }
            connections.forEach((wsIncoming) => {
                const result = new Promise(resolve => wsIncoming.send(BtpPacket.serialize(btpPacket), resolve));
                result.catch(err => {
                    const errorInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err);
                    this._log.debug('unable to send btp message to client: %s; btp packet: %o', errorInfo, btpPacket);
                });
            });
        });
    }
    _addConnection(account, wsIncoming) {
        let connections = this._connections.get(account);
        if (!connections) {
            this._connections.set(account, connections = new Set());
        }
        connections.add(wsIncoming);
    }
    _removeConnection(account, wsIncoming) {
        const connections = this._connections.get(account);
        if (!connections)
            return;
        connections.delete(wsIncoming);
        if (connections.size === 0) {
            this._connections.delete(account);
        }
    }
}
Plugin.version = 2;
exports.default = Plugin;
//# sourceMappingURL=index.js.map