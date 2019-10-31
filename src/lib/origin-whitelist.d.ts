export default class OriginWhitelist {
    private _whitelist;
    constructor(allowedOrigins: string[]);
    add(origin: string): void;
    isOk(origin: string): boolean;
}
