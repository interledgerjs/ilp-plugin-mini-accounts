import { StoreWrapper } from './types';
export default class Token {
    private _account;
    private _hashedToken;
    private _store;
    constructor(opts: {
        account: string;
        store: StoreWrapper;
        token?: string;
        hashedToken?: string;
    });
    equal(otherToken: Token): boolean;
    exists(): boolean;
    save(): void;
    delete(): void;
    static load({ account, store }: {
        account: string;
        store: StoreWrapper;
    }): Promise<Token | null>;
}
