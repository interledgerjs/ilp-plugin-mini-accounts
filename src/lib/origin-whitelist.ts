import * as assert from 'assert'

export default class OriginWhitelist {
  private _whitelist: RegExp[] = []

  constructor (allowedOrigins: string[]) {
    assert(Array.isArray(allowedOrigins), 'parameter allowedOrigins must be an array')
    allowedOrigins.forEach((o) => this._whitelist.push(new RegExp(o)))
  }

  add (origin: string) {
    this._whitelist.push(new RegExp(origin))
  }

  isOk (origin: string) {
    for (const l of this._whitelist) {
      if (l.test(origin)) return true
    }
    return false
  }
}
