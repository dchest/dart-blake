// Written in 2012 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

#library("blake");
#import("dart:crypto");

class BLAKE256 implements Hash {
  
  final blockSize = 32; 
 
  final _MASK_8 = 0xff;
  final _MASK_32 = 0xffffffff;
  final _BYTES_PER_WORD = 4;
  final _ROUNDS = 14;
  
  static final List<List<int>> _SIGMA = const [
      const [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
      const [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
      const [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
      const [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
      const [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
      const [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
      const [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
      const [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
      const [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
      const [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ],
      const [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
      const [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
      const [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
      const [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ]
  ];

  static final List<int> _K =
      const [ 0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
              0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
              0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
              0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917 ];

  // Helper methods.
  _rotr32(x, n) => (x >> n) | ((x << (32 - n)) & _MASK_32);
  _add32(x, y) => (x + y) & _MASK_32;
  
  //TODO(dchest) Add BLAKE-224 implementation and named constructor for it.
  BLAKE256([List<int> salt]) {
    if (salt != null) {
      if (salt.length != _saltSizeInWords * _BYTES_PER_WORD) {
        throw new HashException('Salt length must be 16 bytes');
      }
      _salt = new List(_saltSizeInWords);
      _bytesToWords(salt, 0, _salt, _saltSizeInWords);
    }
    
    // Initialize chain value with IV.
    _h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    _count = [0, 0];
    
    _v = new List(_chunkSizeInWords);
    _currentChunk = new List(_chunkSizeInWords);
    _pendingData = [];
  }
  
  BLAKE256 newInstance() {
    return new BLAKE256();
  }

  BLAKE256 update(List<int> data) {
    if (_digestCalled) {
      throw new HashException(
          'Hash update method called after digest was retrieved');
    }
    _pendingData.addAll(data);
    _iterate();
    return this;
  }
  
  _compressChunk() {
    // Copy state.
    _v.setRange(0, 8, _h);
    // Copy constants.
    _v.setRange(8, 8, _K);
    
    if (_salt != null) {
      _v[ 8] ^= _salt[0];
      _v[ 9] ^= _salt[1];
      _v[10] ^= _salt[2];
      _v[11] ^= _salt[3];
    }
    
    if (!_ignoreCount) {
      _v[12] ^= _count[0];
      _v[13] ^= _count[0];
      _v[14] ^= _count[1];
      _v[15] ^= _count[1];
    }
    
    for (var round = 0; round < _ROUNDS; round++) {
      _G(round, 0, 4,  8, 12,  0);
      _G(round, 1, 5,  9, 13,  2);
      _G(round, 2, 6, 10, 14,  4);
      _G(round, 3, 7, 11, 15,  6);
      _G(round, 3, 4,  9, 14, 14);
      _G(round, 2, 7,  8, 13, 12);
      _G(round, 0, 5, 10, 15,  8);
      _G(round, 1, 6, 11, 12, 10);
    }
    
    for (var i = 0; i < 16; i++) {
      _h[i % 8] ^= _v[i];      
    }
    
    if (_salt == null) return;

    for (var i = 0; i < 8; i++) {
      _h[i] ^= _salt[i % 4];
    }
  }

  _G(r, a, b, c, d, e) {
    _v[a] = _add32(_v[a],
              _add32(_currentChunk[_SIGMA[r][e]] ^ _K[_SIGMA[r][e+1]], _v[b]));
    _v[d] = _rotr32(_v[d] ^ _v[a], 16);
    _v[c] = _add32(_v[c], _v[d]);
    _v[b] = _rotr32(_v[b] ^ _v[c], 12);
    _v[a] = _add32(_v[a],
              _add32(_currentChunk[_SIGMA[r][e+1]] ^ _K[_SIGMA[r][e]], _v[b]));
    _v[d] = _rotr32(_v[d] ^ _v[a], 8);
    _v[c] = _add32(_v[c], _v[d]);
    _v[b] = _rotr32(_v[b] ^ _v[c], 7);
  }

  _iterate() {
    var len = _pendingData.length;
    var chunkSizeInBytes = _chunkSizeInWords * _BYTES_PER_WORD;
    if (len >= chunkSizeInBytes) {
      var index = 0;
      for (; (len - index) >= chunkSizeInBytes; index += chunkSizeInBytes) {
        _bytesToWords(_pendingData, index, _currentChunk, _chunkSizeInWords);
        // Update counter.
        _count[0] = _add32(_count[0], 512);
        if (_count[0] == 0) _count[1]++; 
        _compressChunk();
      }
      var remaining = len - index;
      _pendingData = _pendingData.getRange(index, remaining);
    }
  }
  
  _pad() {
    int pendingBitLen = _pendingData.length * 8;
    
    if (pendingBitLen == 440) {
      // Add one padding byte.
      _count[0] -= 8;
      _pendingData.add(0x81);
      _iterate();
      return;
    }
    
    if (pendingBitLen < 440) {
      // Enough space to fill the block.
      if (pendingBitLen == 0) {
        _ignoreCount = true;
      }
      _count[0] -= 440 - pendingBitLen;
      _pendingData.add(0x80);
      _pendingData.insertRange(_pendingData.length, ((440-pendingBitLen)~/8)-1, 0);
      _iterate();
    } else {
      // Two compressions.
      _count[0] -= 512 - pendingBitLen;
      _pendingData.add(0x80);
      _pendingData.insertRange(_pendingData.length, ((512-pendingBitLen)~/8)-1, 0);
      _iterate();
      _count[0] -= 440;
      _pendingData.insertRange(_pendingData.length, 440~/8, 0);
      _iterate();
      _ignoreCount = true;
    }
    _pendingData.add(0x01);
    _iterate();
    _count[0] -= 8;
  }
 
  _finalize() {
    // Remember message length.
    var pendingBitLen = _pendingData.length * 8;
    var lo = _add32(_count[0], pendingBitLen);
    var hi = _count[1];
    if (lo < pendingBitLen) hi++;
    
    // Compress pending and padding bytes.
    _pad();
    
    // "Append" message length.
    _count[0] -= 64;
    _pendingData.addAll(_wordToBytes(hi));
    _pendingData.addAll(_wordToBytes(lo));
    _iterate();
  }

  // Compute the final result as a list of bytes from the hash words.
  _resultAsBytes() {
    var result = [];
    for (var i = 0; i < _h.length; i++) {
      result.addAll(_wordToBytes(_h[i]));
    }
    return result;
  }

  // Finish the hash computation and return the digest string.
  List<int> digest() {
    if (_digestCalled) {
      return _resultAsBytes();
    }
    _digestCalled = true;
    _finalize();
    assert(_pendingData.length == 0);
    return _resultAsBytes();
  }

  // Converts a list of bytes to a chunk of 32-bit words (big endian).
  _bytesToWords(List<int> data, int dataIndex, List<int> words, int numWords) {
    assert((data.length - dataIndex) >= (numWords * _BYTES_PER_WORD));

    for (var wordIndex = 0; wordIndex < numWords; wordIndex++) {
      words[wordIndex] =
          ((data[dataIndex] & _MASK_8) << 24) |
          ((data[dataIndex + 1] & _MASK_8) << 16) |
          ((data[dataIndex + 2] & _MASK_8) << 8) |
          ((data[dataIndex + 3] & _MASK_8));
      dataIndex += 4;
    }
  }

  // Convert a 32-bit word to four bytes (big endian).
  _wordToBytes(int word) {
    List<int> bytes = new List(_BYTES_PER_WORD);
    bytes[0] = (word >> 24) & _MASK_8;
    bytes[1] = (word >> 16) & _MASK_8;
    bytes[2] = (word >> 8) & _MASK_8;
    bytes[3] = (word >> 0) & _MASK_8;
    return bytes;
  }
  
  // Hasher state.
  List<int> _h;
  List<int> _salt;
  List<int> _count;
  bool _ignoreCount = false;

  List<int> _pendingData;
  List<int> _currentChunk;
  List<int> _v; // temporary space for compression.
  
  final int _chunkSizeInWords = 16;
  final int _saltSizeInWords = 4;
  
  bool _digestCalled = false;
}
