const perf = require('perf_hooks')

class Stats {
  public mean: number = 0
  public count: number = 0

  push (start: number) {
    const dt = this.now() - start
    this.count++
    this.mean += (dt - this.mean) / this.count
  }

  reset () {
    this.count = 0
    this.mean = 0
  }

  now (): number { return perf.performance.now() }
}

module.exports = function (): Stats {
  const stats = new Stats()
  setInterval(function () {
    if (stats.count === 0) return
    console.log('$', stats.mean, 'count=', stats.count)
    stats.reset()
  }, 60000)
  return stats
}
