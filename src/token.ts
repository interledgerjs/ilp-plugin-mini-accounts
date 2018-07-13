import * as assert from 'assert'
import * as crypto from 'crypto'
import { StoreWrapper } from './types'
const BtpPacket = require('btp-packet')

const TOKEN = (account: string): string => account + ':hashed-token'
const DEPRECATED_TOKEN = (account: string): string => account + ':token'

function sha256 (token: string): string {
  return BtpPacket.base64url(crypto.createHash('sha256').update(token).digest())
}

export default class Token {
  private _account: string
  private _hashedToken: string
  private _store: StoreWrapper

  constructor (opts: {
    account: string,
    store: StoreWrapper,
    token?: string,
    hashedToken?: string
  }) {
    this._account = opts.account
    this._store = opts.store
    if (opts.hashedToken) {
      this._hashedToken = opts.hashedToken
    } else if (opts.token) {
      this._hashedToken = sha256(opts.token)
    } else {
      throw new Error('Token: missing parameter: opts.hashedToken or opts.token')
    }
  }

  equal (otherToken: Token): boolean {
    assert(otherToken, 'parameter otherToken is required')
    return this._account === otherToken._account &&
            this._hashedToken === otherToken._hashedToken
  }

  exists (): boolean {
    return !!(this._store && this._store.get(TOKEN(this._account)))
  }

  save () {
    this._store.set(TOKEN(this._account), this._hashedToken)
  }

  delete () {
    this._store.delete(TOKEN(this._account))
  }

  static async load ({ account, store }: {
    account: string,
    store: StoreWrapper
  }): Promise<Token | null> {
    await store.load(TOKEN(account))
    const hashedToken = store.get(TOKEN(account))
    if (hashedToken) {
      return new Token({ account, store, hashedToken })
    }

    await store.load(DEPRECATED_TOKEN(account))
    const token = store.get(DEPRECATED_TOKEN(account))
    if (token) {
      store.set(TOKEN(account), sha256(token))
      store.delete(DEPRECATED_TOKEN(account))
      return new Token({ account, store, token })
    }

    return null
  }
}
