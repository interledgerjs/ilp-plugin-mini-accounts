'use strict'
const debug = require('debug')

class Logger {
  constructor (namespace) {
    this.debug = debug(namespace)
  }

  info (msg) {
    this.debug('INFO: ' + msg)
  }

  warn (msg) {
    this.debug('WARN: ' + msg)
  }

  error (msg) {
    this.debug('ERROR: ' + msg)
  }

  debug (msg) {
    this.debug('DEBUG: ' + msg)
  }
}

function createLogger (namespace) {
  return new Logger(namespace)
}

module.exports = createLogger
