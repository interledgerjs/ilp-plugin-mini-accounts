/// <reference types="node" />
import * as WebSocket from 'ws';
import AbstractBtpPlugin, * as BtpPlugin from 'ilp-plugin-btp';
import * as ILDCP from 'ilp-protocol-ildcp';
import * as IlpPacket from 'ilp-packet';
declare const StoreWrapper: any;
import { Store, StoreWrapper } from './types';
import * as http from 'http';
interface Logger {
    info(...msg: any[]): void;
    warn(...msg: any[]): void;
    error(...msg: any[]): void;
    debug(...msg: any[]): void;
    trace(...msg: any[]): void;
}
export interface IlpPluginMiniAccountsConstructorOptions {
    port?: number;
    wsOpts?: WebSocket.ServerOptions;
    currencyScale?: number;
    debugHostIldcpInfo?: ILDCP.IldcpResponse;
    allowedOrigins?: string[];
    generateAccount?: boolean;
    _store?: Store;
}
export interface IlpPluginMiniAccountsConstructorModules {
    log?: Logger;
    store?: Store;
}
export default class Plugin extends AbstractBtpPlugin {
    static version: number;
    private _port;
    private _wsOpts;
    private _miniAccountsHttpServer;
    protected _currencyScale: number;
    private _debugHostIldcpInfo?;
    protected _log: Logger;
    private _trace;
    private _connections;
    private _allowedOrigins;
    private _accountMode;
    protected _store?: StoreWrapper;
    private _hostIldcpInfo;
    protected _prefix: string;
    protected _handleCustomData: (from: string, btpPacket: BtpPlugin.BtpPacket) => Promise<BtpPlugin.BtpSubProtocol[]>;
    protected _handlePrepareResponse: (destination: string, parsedIlpResponse: IlpPacket.IlpPacket, preparePacket: {
        type: IlpPacket.Type.TYPE_ILP_PREPARE;
        typeString?: 'ilp_prepare';
        data: IlpPacket.IlpPrepare;
    }) => void;
    constructor(opts: IlpPluginMiniAccountsConstructorOptions, { log, store }?: IlpPluginMiniAccountsConstructorModules);
    protected _preConnect(): Promise<void>;
    protected _connect(address: string, authPacket: BtpPlugin.BtpPacket, opts: {
        ws: WebSocket;
        req: http.IncomingMessage;
    }): Promise<void>;
    protected _close(account: string, err?: Error): Promise<void>;
    protected _sendPrepare(destination: string, parsedPacket: IlpPacket.IlpPacket): void;
    ilpAddressToAccount(ilpAddress: string): string;
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    isConnected(): boolean;
    sendData(buffer: Buffer): Promise<Buffer>;
    protected _handleData(from: string, btpPacket: BtpPlugin.BtpPacket): Promise<BtpPlugin.BtpSubProtocol[]>;
    protected _handleOutgoingBtpPacket(to: string, btpPacket: BtpPlugin.BtpPacket): Promise<void>;
    private _addConnection;
    private _removeConnection;
}
export {};
