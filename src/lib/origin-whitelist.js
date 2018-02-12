'use strict'

const assert = require('assert')

class OriginWhitelist {
  constructor (allowedOrigins) {
    this._whitelist = []
    if (allowedOrigins) {
      assert(Array.isArray(allowedOrigins), 'parameter allowedOrigins must be an array')
      allowedOrigins.forEach((o) => this._whitelist.push(new RegExp(o)))
    }
  }

  add (origin) {
    this._whitelist.push(new RegExp(origin))
  }

  isOk (origin) {
    assert(typeof origin === 'string', 'parameter origin must be string')
    for (const l of this._whitelist) {
      if (l.test(origin)) return true
    }
    return false
  }
}

module.exports = OriginWhitelist
