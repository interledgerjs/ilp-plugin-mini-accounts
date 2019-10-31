const perf = require('perf_hooks');
class Stats {
    constructor() {
        this.mean = 0;
        this.count = 0;
    }
    push(start) {
        const dt = this.now() - start;
        this.count++;
        this.mean += (dt - this.mean) / this.count;
    }
    reset() {
        this.count = 0;
        this.mean = 0;
    }
    now() { return perf.performance.now(); }
}
module.exports = function () {
    const stats = new Stats();
    setInterval(function () {
        if (stats.count === 0)
            return;
        console.log('$', stats.mean, 'count=', stats.count);
        stats.reset();
    }, 60000);
    return stats;
};
//# sourceMappingURL=bench.js.map