const int64 = require('int64')

function toBuffer (str) {
  return Buffer.from(int64.dec2hex(str), 'hex')
}

function toString (buf) {
  return int64.hex2dec(buf.toString('hex'))
}

module.exports = {
  toBuffer,
  toString
}
