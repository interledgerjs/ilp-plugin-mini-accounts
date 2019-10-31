"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require("assert");
class OriginWhitelist {
    constructor(allowedOrigins) {
        this._whitelist = [];
        assert(Array.isArray(allowedOrigins), 'parameter allowedOrigins must be an array');
        allowedOrigins.forEach((o) => this._whitelist.push(new RegExp(o)));
    }
    add(origin) {
        this._whitelist.push(new RegExp(origin));
    }
    isOk(origin) {
        for (const l of this._whitelist) {
            if (l.test(origin))
                return true;
        }
        return false;
    }
}
exports.default = OriginWhitelist;
//# sourceMappingURL=origin-whitelist.js.map