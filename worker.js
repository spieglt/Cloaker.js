// import * as c from './constants.js';
let c = {
  crypto_pwhash_argon2id_SALTBYTES: 16,
  CHUNKSIZE: 1024 * 512,
  LEGACY_CHUNKSIZE: 4096,
  SIGNATURE: new Uint8Array([0xC1, 0x0A, 0x6B, 0xED]),
  LEGACY_SIGNATURE: new Uint8Array([0xC1, 0x0A, 0x4B, 0xED]),
  EXTENSION: '.cloaker',
  START_ENCRYPTION: 'startEncryption',
  ENCRYPT_CHUNK: 'encryptChunk',
  ENCRYPTED_CHUNK: 'encryptedChunk',
  START_DECRYPTION: 'startDecryption',
  DECRYPT_CHUNK: 'decryptChunk',
  DECRYPTED_CHUNK: 'decryptedChunk',
  INITIALIZED_ENCRYPTION: 'initializedEncryption',
  INITIALIZED_DECRYPTION: 'initializedDecryption',
  FINAL_ENCRYPTION: 'finalEncryption',
  FINAL_DECRYPTION: 'finalDecryption',
  DECRYPTION_FAILED: 'decryptionFailed',
};

const hydrate = (sodium) => {
  console.log('sodium initialized in worker');
  let state, inFile, offset;
  let legacy = false;

  const startEncryption = (message) => {
    let { password, salt } = message.data;
    inFile = message.data.inFile;
    offset = 0;

    let key = sodium.crypto_pwhash(32, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    let res = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    state = res.state;
    let header = res.header;
    postMessage({ response: c.INITIALIZED_ENCRYPTION, header });
  }

  const encryptChunk = async (message) => {
    let chunkSize = Math.min(c.CHUNKSIZE, inFile.size - offset);
    let chunk = await inFile.slice(offset, offset + chunkSize).arrayBuffer();
    chunk = new Uint8Array(chunk);
    offset += chunkSize;
    let tag = offset < inFile.size - 1
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    const response = tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      ? c.FINAL_ENCRYPTION
      : c.ENCRYPTED_CHUNK;
    const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, null, tag);
    const progress = Math.floor((offset/inFile.size)*100);
    postMessage({ response, progress, encryptedChunk });
  }

  const startDecryption = async (message) => {
    let { password } = message.data;
    inFile = message.data.inFile;
    let salt, header, key;
    let firstFour = await inFile.slice(0, 4).arrayBuffer();
    if (compareArrays(firstFour, c.SIGNATURE)) {
      offset = 4; // skip signature
      salt = await inFile.slice(offset, offset + c.crypto_pwhash_argon2id_SALTBYTES).arrayBuffer();
      salt = new Uint8Array(salt);
      offset += c.crypto_pwhash_argon2id_SALTBYTES;
      header = await inFile.slice(offset, offset + sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES).arrayBuffer();
      header = new Uint8Array(header);
      offset += sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
      key = sodium.crypto_pwhash(32, password, salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_ARGON2ID13
      );
    } else {
      legacy = true;
      offset = compareArrays(firstFour, c.LEGACY_SIGNATURE) ? 4 : 0; // skip signature
      salt = await inFile.slice(offset, offset + sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES).arrayBuffer();
      offset += sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
      header = await inFile.slice(offset, offset + sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES).arrayBuffer();
      header = new Uint8Array(header);
      offset += sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
      key = sodium.crypto_pwhash_scryptsalsa208sha256(32, password, salt,
        sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    }

    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
    postMessage({ response: c.INITIALIZED_DECRYPTION, header });
  }

  const decryptChunk = async (message) => {
    let chunkSize = legacy ? c.LEGACY_CHUNKSIZE : c.CHUNKSIZE;
    chunkSize = Math.min(chunkSize + sodium.crypto_secretstream_xchacha20poly1305_ABYTES, inFile.size - offset);
    let chunk = await inFile.slice(offset, offset + chunkSize).arrayBuffer();
    chunk = new Uint8Array(chunk);
    offset += chunkSize;
    let res = sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk);
    if (!res) {
      postMessage({ response: c.DECRYPTION_FAILED });
      return;
    }
    let decryptedChunk = res.message;
    const progress = Math.floor((offset/inFile.size)*100);
    let response = res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      ? c.FINAL_DECRYPTION
      : c.DECRYPTED_CHUNK;
    postMessage({ response, progress, decryptedChunk });
  }

  onmessage = (message) => {
    // console.log('worker received:', message);
    switch(message.data.command) {
      case c.START_ENCRYPTION:
        startEncryption(message);
        break;
      case c.ENCRYPT_CHUNK:
        encryptChunk(message);
        break;
      case c.START_DECRYPTION:
        startDecryption(message);
        break;
      case c.DECRYPT_CHUNK:
        decryptChunk(message);
        break;
    }
  };
}
self.sodium = { onload: hydrate };
importScripts('./sodium.js');

const compareArrays = (a1, a2) => {
  if (!a1.length || a1.length != a2.length) {
    return false;
  }
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}
