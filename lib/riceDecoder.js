"use strict";

class RiceDecoder {
  constructor(encodedData, riceParameter) {
    this._encodedData = encodedData;
    this._riceParameter = riceParameter;
    this._br = {
      buf: encodedData,
      mask: 1
    };
  }

  readBits(br, n) {
    let v = 0;
    for (var i = 0; i < n; i++) {
      if (br.buf[0] & br.mask) {
        v |= 1 << i;
      }
      br.mask <<= 1;
      if (br.mask % 256 === 0) {
        br.buf = br.buf.slice(1);
        br.mask = 1;
      }
    }
    return v;
  }

  readValue() {
    let q = 0;
    while (true) {
      let bit = this.readBits(this._br, 1);
      q += bit;
      if (bit === 0) break;
    }
    let r = this.readBits(this._br, this._riceParameter);
    return (q << this._riceParameter) + r;
  }
}

module.exports = RiceDecoder;
