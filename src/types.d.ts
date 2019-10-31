export interface Store {
    get(key: string): Promise<string | void>;
    put(key: string, value: string): Promise<void>;
    del(key: string): Promise<void>;
}
export interface StoreWrapper {
    load(key: string): Promise<void>;
    get(key: string): string;
    set(key: string, value: string): void;
    delete(key: string): void;
    setCache(key: string, value: string): void;
}
