declare const perf: any;
declare class Stats {
    mean: number;
    count: number;
    push(start: number): void;
    reset(): void;
    now(): number;
}
