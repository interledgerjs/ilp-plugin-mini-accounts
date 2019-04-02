import * as crypto from 'crypto'
const BtpPacket = require('btp-packet')
import * as WebSocket from 'ws'
import * as assert from 'assert'
import AbstractBtpPlugin, * as BtpPlugin from 'ilp-plugin-btp'
import * as ILDCP from 'ilp-protocol-ildcp'
import * as IlpPacket from 'ilp-packet'
const { Errors } = IlpPacket
const StoreWrapper = require('ilp-store-wrapper')
import OriginWhitelist from './lib/origin-whitelist'
import Token from './token'
import { Store, StoreWrapper } from './types'
const createLogger = require('ilp-logger')
import * as http from 'http'
import * as https from 'https'

const DEBUG_NAMESPACE = 'ilp-plugin-mini-accounts'

function tokenToAccount (token: string): string {
  return BtpPacket.base64url(crypto.createHash('sha256').update(token).digest())
}

interface Logger {
  info (...msg: any[]): void
  warn (...msg: any[]): void
  error (...msg: any[]): void
  debug (...msg: any[]): void
  trace (...msg: any[]): void
}

export interface IlpPluginMiniAccountsConstructorOptions {
  port?: number
  wsOpts?: WebSocket.ServerOptions
  currencyScale?: number
  debugHostIldcpInfo?: ILDCP.IldcpResponse
  allowedOrigins?: string[]
  generateAccount?: boolean
  _store?: Store
}

export interface IlpPluginMiniAccountsConstructorModules {
  log?: Logger
  store?: Store
}

enum AccountMode {
  // Account is set using the `auth_username` BTP subprotocol.
  // A store is required in this mode.
  Username,
  // Account is set to sha256(token). The `auth_username` subprotocol is disallowed.
  HashToken,
  // Account is set to `auth_username` if available, otherwise  sha256(token) is used.
  UsernameOrHashToken
}

function accountModeIsStored (mode: AccountMode): boolean {
  return mode === AccountMode.Username || mode === AccountMode.UsernameOrHashToken
}

/* tslint:disable-next-line:no-empty */
function noopTrace (...msg: any[]): void { }

export default class Plugin extends AbstractBtpPlugin {
  static version = 2

  private _port: number
  private _wsOpts: WebSocket.ServerOptions
  private _httpServer: http.Server | https.Server
  protected _currencyScale: number
  private _debugHostIldcpInfo?: ILDCP.IldcpResponse
  protected _log: Logger
  private _trace: (...msg: any[]) => void
  private _connections: Map<string, Set<WebSocket>> = new Map()
  private _allowedOrigins: OriginWhitelist
  private _accountMode: AccountMode
  protected _store?: StoreWrapper

  private _hostIldcpInfo: ILDCP.IldcpResponse
  protected _prefix: string
  // These can be overridden.
  // TODO can this be overridden via `extends`??
  protected _handleCustomData: (from: string, btpPacket: BtpPlugin.BtpPacket) => Promise<BtpPlugin.BtpSubProtocol[]>
  protected _handlePrepareResponse: (destination: string, parsedIlpResponse: IlpPacket.IlpPacket, preparePacket: {
    type: IlpPacket.Type.TYPE_ILP_PREPARE,
    typeString?: 'ilp_prepare',
    data: IlpPacket.IlpPrepare
  }) => void

  constructor (opts: IlpPluginMiniAccountsConstructorOptions,
    { log, store }: IlpPluginMiniAccountsConstructorModules = {}) {
    super({})
    if (opts.wsOpts && opts.wsOpts.port && opts.port) {
      throw new Error('Specify at most one of: `ops.wsOpts.port`, `opts.port`.')
    } else if (opts.wsOpts && opts.wsOpts.port) {
      this._port = opts.wsOpts.port
    } else if (opts.port) {
      this._port = opts.port
    } else {
      this._port = 3000
    }
    this._wsOpts = opts.wsOpts || { port: this._port }
    if (this._wsOpts.server) {
      this._httpServer = this._wsOpts.server
    }
    this._currencyScale = opts.currencyScale || 9
    this._debugHostIldcpInfo = opts.debugHostIldcpInfo

    const _store = store || opts._store
    this._accountMode = _store ? AccountMode.UsernameOrHashToken : AccountMode.HashToken
    if (opts.generateAccount === true) this._accountMode = AccountMode.HashToken
    if (opts.generateAccount === false) {
      if (!_store) {
        throw new Error('_store is required when generateAccount is false')
      }
      this._accountMode = AccountMode.Username
    }

    this._log = log || createLogger(DEBUG_NAMESPACE)
    this._log.trace = this._log.trace || noopTrace

    this._allowedOrigins = new OriginWhitelist(opts.allowedOrigins || [])

    if (_store) {
      this._store = new StoreWrapper(_store)
    }
  }

  /* tslint:disable:no-empty */
  // These can be overridden.
  protected async _preConnect (): Promise<void> {}
  // plugin-btp and plugin-mini-accounts use slightly different signatures for _connect
  // making the mini-accounts params optional makes them kinda compatible
  protected async _connect (address: string, authPacket: BtpPlugin.BtpPacket, opts: {
    ws: WebSocket,
    req: http.IncomingMessage
  }): Promise<void> {}
  protected async _close (account: string, err?: Error): Promise<void> {}
  protected _sendPrepare (destination: string, parsedPacket: IlpPacket.IlpPacket): void {}
  /* tslint:enable:no-empty */

  ilpAddressToAccount (ilpAddress: string): string {
    if (ilpAddress.substr(0, this._prefix.length) !== this._prefix) {
      throw new Error('ILP address (' + ilpAddress + ') must start with prefix (' + this._prefix + ')')
    }

    return ilpAddress.substr(this._prefix.length).split('.')[0]
  }

  async connect (): Promise<void> {
    if (this._wss) return

    if (this._debugHostIldcpInfo) {
      this._hostIldcpInfo = this._debugHostIldcpInfo
    } else if (this._dataHandler) {
      this._hostIldcpInfo = await ILDCP.fetch(this._dataHandler.bind(this))
    } else {
      throw new Error('no request handler registered')
    }

    this._prefix = this._hostIldcpInfo.clientAddress + '.'

    if (this._preConnect) {
      try {
        await this._preConnect()
      } catch (err) {
        this._log.debug(`Error on _preConnect. Reason is: ${err.message}`)
        throw new Error('Failed to connect')
      }
    }

    this._log.info('listening on port ' + this._port)

    if (this._httpServer) {
      this._httpServer.listen(this._port)
    }
    const wss = this._wss = new WebSocket.Server(this._wsOpts)
    wss.on('connection', (wsIncoming, req) => {
      this._log.trace('got connection')
      if (typeof req.headers.origin === 'string' && !this._allowedOrigins.isOk(req.headers.origin)) {
        this._log.debug(`Closing a websocket connection received from a browser. Origin is ${req.headers.origin}`)
        this._log.debug('If you are running moneyd, you may allow this origin with the flag --allow-origin.' +
          ' Run moneyd --help for details.')
        wsIncoming.close()
        return
      }

      let token: string
      let account: string

      const closeHandler = (error?: Error) => {
        this._log.debug('incoming ws closed. error=', error)
        if (account) this._removeConnection(account, wsIncoming)
        if (this._close) {
          this._close(this._prefix + account, error)
            .catch(e => {
              this._log.debug('error during custom close handler. error=', e)
            })
        }
      }

      wsIncoming.on('close', closeHandler)
      wsIncoming.on('error', closeHandler)

      // The first message must be an auth packet
      // with the macaroon as the auth_token
      let authPacket: BtpPlugin.BtpPacket
      wsIncoming.once('message', async (binaryAuthMessage) => {
        try {
          authPacket = BtpPacket.deserialize(binaryAuthMessage)
          assert.strictEqual(authPacket.type, BtpPacket.TYPE_MESSAGE, 'First message sent over BTP connection must be auth packet')
          assert(authPacket.data.protocolData.length >= 2, 'Auth packet must have auth and auth_token subprotocols')
          assert.strictEqual(authPacket.data.protocolData[0].protocolName, 'auth', 'First subprotocol must be auth')
          for (let subProtocol of authPacket.data.protocolData) {
            if (subProtocol.protocolName === 'auth_token') {
              // TODO: Do some validation on the token
              token = subProtocol.data.toString()
            } else if (subProtocol.protocolName === 'auth_username') {
              account = subProtocol.data.toString()
            }
          }
          assert(token, 'auth_token subprotocol is required')

          switch (this._accountMode) {
            case AccountMode.Username:
              assert(account, 'auth_username subprotocol is required')
              break
            case AccountMode.HashToken:
              assert(!account || account === tokenToAccount(token),
                'auth_username subprotocol is not available')
              break
          }
          // Default the account to sha256(token).
          if (!account) account = tokenToAccount(token)

          this._addConnection(account, wsIncoming)

          this._log.trace('got auth info. token=' + token, 'account=' + account)
          if (accountModeIsStored(this._accountMode) && this._store) {
            const storedToken = await Token.load({ account, store: this._store })
            const receivedToken = new Token({ account, token, store: this._store })
            if (storedToken) {
              if (!storedToken.equal(receivedToken)) {
                throw new Error('incorrect token for account.' +
                  ' account=' + account +
                  ' token=' + token)
              }
            } else {
              receivedToken.save()
            }
          }

          if (this._connect) {
            await this._connect(this._prefix + account, authPacket, {
              ws: wsIncoming,
              req
            })
          }

          wsIncoming.send(BtpPacket.serializeResponse(authPacket.requestId, []))
        } catch (err) {
          if (authPacket) {
            this._log.debug('not accepted error during auth. error=', err)
            const errorResponse = BtpPacket.serializeError({
              code: 'F00',
              name: 'NotAcceptedError',
              data: err.message || err.name,
              triggeredAt: new Date().toISOString()
            }, authPacket.requestId, [])
            wsIncoming.send(errorResponse) // TODO throws error "not opened"
          }
          wsIncoming.close()
          return
        }

        this._log.trace('connection authenticated')

        wsIncoming.on('message', async (binaryMessage) => {
          let btpPacket
          try {
            btpPacket = BtpPacket.deserialize(binaryMessage)
          } catch (err) {
            wsIncoming.close()
            return
          }
          this._log.trace(`account ${account}: processing btp packet ${JSON.stringify(btpPacket)}`)
          try {
            this._log.trace('packet is authorized, forwarding to host')
            await this._handleIncomingBtpPacket(this._prefix + account, btpPacket)
          } catch (err) {
            this._log.debug('btp packet not accepted', err)
            const errorResponse = BtpPacket.serializeError({
              code: 'F00',
              name: 'NotAcceptedError',
              triggeredAt: new Date().toISOString(),
              data: err.message
            }, btpPacket.requestId, [])
            wsIncoming.send(errorResponse)
          }
        })
      })
    })
  }

  async disconnect () {
    if (this._disconnect) {
      await this._disconnect()
    }

    if (this._wss) {
      const wss = this._wss
      // Close the websocket server
      await new Promise((resolve) => wss.close(resolve))
      // The above doesn't wait until the individual sockets have been closed. So they wouldn't be removed before this function returns.
      // Remove the individual sockets manually
      this._connections.clear()

      if (this._httpServer) {
        await new Promise((resolve) => {
          this._httpServer.close(resolve)
        })
      }
      this._wss = null
    }
  }

  isConnected () {
    return !!this._wss
  }

  async sendData (buffer: Buffer): Promise<Buffer> {
    const parsedPacket = IlpPacket.deserializeIlpPacket(buffer)
    if (parsedPacket.type !== IlpPacket.Type.TYPE_ILP_PREPARE) {
      throw new Error(`can't route packet that's not a PREPARE.`)
    }
    const { destination, expiresAt, executionCondition } = parsedPacket.data

    if (this._sendPrepare) {
      this._sendPrepare(destination, parsedPacket)
    }

    if (destination === 'peer.config') {
      return ILDCP.serializeIldcpResponse(this._hostIldcpInfo)
    }

    if (!destination.startsWith(this._prefix)) {
      throw new Error(`can't route packet that is not meant for one of my clients. destination=${destination} prefix=${this._prefix}`)
    }

    let timeout: NodeJS.Timer
    const duration = expiresAt.getTime() - Date.now()

    const timeoutPacket = () =>
      IlpPacket.serializeIlpReject({
        code: 'R00',
        message: 'Packet expired',
        triggeredBy: this._hostIldcpInfo.clientAddress,
        data: Buffer.alloc(0)
      })

    // Set timeout to expire the ILP packet
    const timeoutPromise = new Promise<Buffer>(resolve => {
      timeout = setTimeout(() => resolve(
        timeoutPacket()
      ), duration)
    })

    // Forward ILP packet to peer over BTP
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
    }).then(response =>
      // Extract the ILP packet from the BTP response
      response.protocolData.filter(p => p.protocolName === 'ilp')[0].data
    )

    const ilpResponse = await Promise.race([
      timeoutPromise,
      responsePromise
    ])

    /* tslint:disable-next-line:no-unnecessary-type-assertion */
    clearTimeout(timeout!)

    const parsedIlpResponse = IlpPacket.deserializeIlpPacket(ilpResponse)

    if (parsedIlpResponse.type === IlpPacket.Type.TYPE_ILP_FULFILL) {
      // In case the plugin is overloaded with events, confirm the FULFILL hasn't expired
      const isExpired = Date.now() > expiresAt.getTime()
      if (isExpired) {
        return timeoutPacket()
      }

      const { fulfillment } = parsedIlpResponse.data
      if (!crypto.createHash('sha256')
        .update(fulfillment)
        .digest()
        .equals(executionCondition)) {
        return IlpPacket.errorToReject(this._hostIldcpInfo.clientAddress,
          new Errors.WrongConditionError(
            'condition and fulfillment don\'t match. ' +
            `condition=${executionCondition.toString('hex')} ` +
            `fulfillment=${fulfillment.toString('hex')}`))
      }
    }

    if (this._handlePrepareResponse) {
      try {
        this._handlePrepareResponse(destination, parsedIlpResponse, parsedPacket)
      } catch (e) {
        return IlpPacket.errorToReject(this._hostIldcpInfo.clientAddress, e)
      }
    }

    return ilpResponse || Buffer.alloc(0)
  }

  protected async _handleData (from: string, btpPacket: BtpPlugin.BtpPacket): Promise<BtpPlugin.BtpSubProtocol[]> {
    const { ilp } = this.protocolDataToIlpAndCustom(btpPacket.data)

    if (ilp) {
      const parsedPacket = IlpPacket.deserializeIlpPacket(ilp)

      if (parsedPacket.data['destination'] === 'peer.config') {
        this._log.trace('responding to ILDCP request. clientAddress=%s', from)
        return [{
          protocolName: 'ilp',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: await ILDCP.serve({
            requestPacket: ilp,
            handler: async () => ({
              ...this._hostIldcpInfo,
              clientAddress: from
            }),
            serverAddress: this._hostIldcpInfo.clientAddress
          })
        }]
      }
    }

    if (this._handleCustomData) {
      this._log.trace('passing non-ILDCP data to custom handler')
      return this._handleCustomData(from, btpPacket)
    }

    if (!ilp) {
      this._log.debug('invalid packet, no ilp protocol data. from=%s', from)
      throw new Error('invalid packet, no ilp protocol data.')
    }

    if (!this._dataHandler) {
      throw new Error('no request handler registered')
    }

    const response = await this._dataHandler(ilp)
    return this.ilpAndCustomToProtocolData({ ilp: response })
  }

  protected async _handleOutgoingBtpPacket (to: string, btpPacket: BtpPlugin.BtpPacket) {
    if (!to.startsWith(this._prefix)) {
      throw new Error(`invalid destination, must start with prefix. destination=${to} prefix=${this._prefix}`)
    }

    const account = this.ilpAddressToAccount(to)
    const connections = this._connections.get(account)

    if (!connections) {
      throw new Error('No clients connected for account ' + account)
    }

    Array.from(connections).map(wsIncoming => {
      const result = new Promise(resolve => wsIncoming.send(BtpPacket.serialize(btpPacket), resolve))

      result.catch(err => {
        const errorInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err)
        this._log.debug('unable to send btp message to client: ' + errorInfo, 'btp packet:', JSON.stringify(btpPacket))
      })
    })
  }

  private _addConnection (account: string, wsIncoming: WebSocket) {
    let connections = this._connections.get(account)
    if (!connections) {
      this._connections.set(account, connections = new Set())
    }
    connections.add(wsIncoming)
  }

  private _removeConnection (account: string, wsIncoming: WebSocket) {
    const connections = this._connections.get(account)
    if (!connections) return
    connections.delete(wsIncoming)
    if (connections.size === 0) {
      this._connections.delete(account)
    }
  }
}
