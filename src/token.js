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
const assert = require("assert");
const crypto = require("crypto");
const BtpPacket = require('btp-packet');
const TOKEN = (account) => account + ':hashed-token';
const DEPRECATED_TOKEN = (account) => account + ':token';
function sha256(token) {
    return BtpPacket.base64url(crypto.createHash('sha256').update(token).digest());
}
class Token {
    constructor(opts) {
        this._account = opts.account;
        this._store = opts.store;
        if (opts.hashedToken) {
            this._hashedToken = opts.hashedToken;
        }
        else if (opts.token) {
            this._hashedToken = sha256(opts.token);
        }
        else {
            throw new Error('Token: missing parameter: opts.hashedToken or opts.token');
        }
    }
    equal(otherToken) {
        assert(otherToken, 'parameter otherToken is required');
        return this._account === otherToken._account &&
            this._hashedToken === otherToken._hashedToken;
    }
    exists() {
        return !!(this._store && this._store.get(TOKEN(this._account)));
    }
    save() {
        this._store.set(TOKEN(this._account), this._hashedToken);
    }
    delete() {
        this._store.delete(TOKEN(this._account));
    }
    static load({ account, store }) {
        return __awaiter(this, void 0, void 0, function* () {
            yield store.load(TOKEN(account));
            const hashedToken = store.get(TOKEN(account));
            if (hashedToken) {
                return new Token({ account, store, hashedToken });
            }
            yield store.load(DEPRECATED_TOKEN(account));
            const token = store.get(DEPRECATED_TOKEN(account));
            if (token) {
                store.set(TOKEN(account), sha256(token));
                store.delete(DEPRECATED_TOKEN(account));
                return new Token({ account, store, token });
            }
            return null;
        });
    }
}
exports.default = Token;
//# sourceMappingURL=token.js.map