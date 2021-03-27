const crypto_pwhash_argon2id_SALTBYTES = 16;
const CHUNKSIZE = 1024 * 512;
const LEGACY_CHUNKSIZE = 4096;
const SIGNATURE = new Uint8Array([0xC1, 0x0A, 0x6B, 0xED]);
const LEGACY_SIGNATURE = new Uint8Array([0xC1, 0x0A, 0x4B, 0xED]);

const hydrate = (sodium) => {
  console.log('sodium initialized in worker');
  let state, inBuffer, offset;
  let legacy = false;

  const startEncryption = (message) => {
    let { password, salt } = message.data;
    inBuffer = new Uint8Array(message.data.inBuffer);
    offset = 0;

    let key = sodium.crypto_pwhash(32, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    let res = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    state = res.state;
    let header = res.header;
    postMessage({ response: 'initializedEncryption', header });
  }

  const encryptChunk = (message) => {
    let chunkSize = Math.min(CHUNKSIZE, inBuffer.byteLength - offset);
    let chunk = inBuffer.slice(offset, offset + chunkSize);
    offset += chunkSize;
    let tag = offset < inBuffer.byteLength - 1
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    const response = tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      ? 'finalEncryption'
      : 'encryptedChunk';
    const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, null, tag);
    const progress = `encrypting... ${((offset/inBuffer.byteLength)*100).toFixed()}%`;
    postMessage({ response, progress, encryptedChunk });
  }

  const startDecryption = (message) => {
    let { password } = message.data;
    inBuffer = new Uint8Array(message.data.inBuffer);
    let salt, header, key;
    if (compareArrays(inBuffer.slice(0, 4), SIGNATURE)) {
      offset = 4; // skip signature
      salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);
      salt.set(inBuffer.slice(offset, offset + crypto_pwhash_argon2id_SALTBYTES));
      offset += crypto_pwhash_argon2id_SALTBYTES;
      header = inBuffer.slice(offset, offset + sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES);
      offset += sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
      key = sodium.crypto_pwhash(32, password, salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_ARGON2ID13
      );
    } else if (compareArrays(inBuffer.slice(0, 4), LEGACY_SIGNATURE) || extensionIsCloaker(message.data.fileName)) {
      legacy = true;
      offset = compareArrays(inBuffer.slice(0, 4), LEGACY_SIGNATURE) ? 4 : 0; // skip signature
      salt = new Uint8Array(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
      salt.set(inBuffer.slice(offset, offset + sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES));
      offset += sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
      header = inBuffer.slice(offset, offset + sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES);
      offset += sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
      key = sodium.crypto_pwhash_scryptsalsa208sha256(32, password, salt,
        sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    } else {
      postMessage({ response: 'notCloaker' });
      return;
    }

    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
    postMessage({ response: 'initializedDecryption', header });
  }

  const decryptChunk = (message) => {
    let chunkSize = legacy ? LEGACY_CHUNKSIZE : CHUNKSIZE;
    chunkSize = Math.min(chunkSize + sodium.crypto_secretstream_xchacha20poly1305_ABYTES, inBuffer.byteLength - offset);
    let chunk = inBuffer.slice(offset, offset + chunkSize);
    offset += chunkSize;
    let res = sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk);
    if (!res) {
      postMessage({ response: 'decryptionFailed' });
      return;
    }
    let decryptedChunk = res.message;
    const progress = `decrypting... ${((offset/inBuffer.byteLength)*100).toFixed()}%`;
    let response = res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      ? 'finalDecryption'
      : 'decryptedChunk';
    postMessage({ response, progress, decryptedChunk });
  }

  onmessage = (message) => {
    // console.log('worker received:', message);
    switch(message.data.command) {
      case 'startEncryption':
        startEncryption(message);
        break;
      case 'encryptChunk':
        encryptChunk(message);
        break;
      case 'startDecryption':
        startDecryption(message);
        break;
      case 'decryptChunk':
        decryptChunk(message);
        break;
    }
  };
}
self.sodium = { onload: hydrate };
importScripts('sodium.js');

const compareArrays = (a1, a2) => {
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}

const extensionIsCloaker = (fileName) => {
  return fileName.length > '.cloaker'.length
    && fileName.slice(fileName.length - '.cloaker'.length, fileName.length) === '.cloaker'
}
