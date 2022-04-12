import * as c from './constants.js';
// let c = {
//   crypto_pwhash_argon2id_SALTBYTES: 16,
//   CHUNKSIZE: 1024 * 512,
//   LEGACY_CHUNKSIZE: 4096,
//   SIGNATURE: new Uint8Array([0xC1, 0x0A, 0x6B, 0xED]),
//   LEGACY_SIGNATURE: new Uint8Array([0xC1, 0x0A, 0x4B, 0xED]),
//   EXTENSION: '.cloaker',
//   START_ENCRYPTION: 'startEncryption',
//   ENCRYPT_CHUNK: 'encryptChunk',
//   ENCRYPTED_CHUNK: 'encryptedChunk',
//   START_DECRYPTION: 'startDecryption',
//   DECRYPT_CHUNK: 'decryptChunk',
//   DECRYPTED_CHUNK: 'decryptedChunk',
//   INITIALIZED_ENCRYPTION: 'initializedEncryption',
//   INITIALIZED_DECRYPTION: 'initializedDecryption',
//   FINAL_ENCRYPTION: 'finalEncryption',
//   FINAL_DECRYPTION: 'finalDecryption',
//   DECRYPTION_FAILED: 'decryptionFailed',
//   NOT_CLOAKER: 'notCloaker',
// };

let inFile;
let filename;
let outFile;
let outFilename;
let startEncryption;
let encryptChunk;
let startDecryption;
let decryptChunk;
let selectFileButton;
let selectFileElem;
let encryptButton;
let encryptElem;
let decryptButton;
let decryptElem;
let passwordTitle;
let passwordBox;
let outputBox;
let progressBar;

window.onload = () => {
  selectFileButton = document.getElementById('selectFileButton');
  selectFileElem = document.getElementById('selectFileElem');
  encryptButton = document.getElementById('encryptButton');
  encryptElem = document.getElementById('encryptElem');
  decryptButton = document.getElementById('decryptButton');
  decryptElem = document.getElementById('decryptElem');
  passwordTitle = document.getElementById('passwordTitle');
  passwordBox = document.getElementById('passwordBox');
  outputBox = document.getElementById('outputBox');
  progressBar = document.getElementById('progressBar');

  selectFileButton.onclick = () => selectFileElem.click();
  selectFileElem.oninput = async () => {
    inFile = selectFileElem.files[0];
    let firstFour = await inFile.slice(0, 4).arrayBuffer();
    firstFour = new Uint8Array(firstFour);
    let hasSignature = compareArrays(firstFour, c.SIGNATURE)
      || compareArrays(firstFour, c.LEGACY_SIGNATURE);
    let decrypting = extensionIsCloaker(inFile.name) || hasSignature;
    if (decrypting) {
      encryptButton.style = 'display: hidden';
      decryptButton.style = 'display: unset';
    } else {
      encryptButton.style = 'display: unset';
      decryptButton.style = 'display: hidden';
    }

    outFilename = decrypting
      ? getDecryptFilename(inFile.name)
      : inFile.name + c.EXTENSION;
    output(`Output filename: ${outFilename}`);
  }

  encryptButton.onclick = async () => {
    if (!inFile) {
      output('Please select file.');
    }
    const password = passwordBox.value;
    if (password.length < 12) {
      passwordBox.classList.add('passwordError');
      setTimeout(() => {
        passwordBox.classList.remove('passwordError');
      }, 1000);
      passwordTitle.classList.add('passwordErrorTitle');
      setTimeout(() => {
        passwordTitle.classList.remove('passwordErrorTitle');
      }, 4000);
      return;
    }
    outFile = await window.showSaveFilePicker({
      suggestedName: outFilename,
      types: [{
        description: 'Cloaker',
        accept: {'application/cloaker': [c.EXTENSION]},
      }],
    });
    startEncryption(inFile, password);
  };

  decryptButton.onclick = async () => {
    if (!inFile) {
      output('Please select file.');
    }
    const password = passwordBox.value;
    outFile = await window.showSaveFilePicker({
      suggestedName: outFilename,
      types: [{
        description: 'Cloaker',
        accept: {'application/cloaker': [c.EXTENSION]},
      }],
    });
    startDecryption(inFile, password);
  };
};

let worker = new Worker('./worker.js');

worker.onmessage = (message) => {
  // console.log('main received:', message);
  switch (message.data.response) {
    case c.INITIALIZED_ENCRYPTION:
      outBuffers.push(message.data.header);
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // kick off actual encryption
      break;
    case c.ENCRYPTED_CHUNK:
      outBuffers.push(message.data.encryptedChunk);
      updateProgress(message.data.progress);
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // next chunk
      break;
    case c.FINAL_ENCRYPTION:
      outBuffers.push(message.data.encryptedChunk);
      updateProgress(message.data.progress);
      output(`Encryption of ${outFilename} complete.`);
      break;
    case c.INITIALIZED_DECRYPTION:
      worker.postMessage({ command: c.DECRYPT_CHUNK }); // kick off decryption
      break;
    case c.DECRYPTED_CHUNK:
      outBuffers.push(message.data.decryptedChunk);
      updateProgress(message.data.progress);
      worker.postMessage({ command: c.DECRYPT_CHUNK });
      break;
    case c.FINAL_DECRYPTION:
      outBuffers.push(message.data.decryptedChunk);
      updateProgress(message.data.progress);
      output(`Decryption of ${outFilename} complete.`);      
      break;
    case c.DECRYPTION_FAILED:
      output('Incorrect password');
      break;
    case c.NOT_CLOAKER:
      output('File was not encrypted with Cloaker');
      break;
  }
};

startEncryption = async (inFile, password) => {
  inBuffer = await inFile.arrayBuffer();
  outBuffers = [new Uint8Array(c.SIGNATURE)];
  filename = inFile.name;
  output(`Filename: ${filename}, size: ${inBuffer.byteLength}`);
  let salt = new Uint8Array(c.crypto_pwhash_argon2id_SALTBYTES);
  window.crypto.getRandomValues(salt);
  outBuffers.push(salt);
  worker.postMessage({ inBuffer, password, salt, command: c.START_ENCRYPTION }, [inBuffer]); // make sure to transfer inBuffer, not clone
}

// as of now, we hand the entire input to the thread
// when streaming, we hand the file handle to the thread
const startEncryptionStreaming = async (inFile, password) => {
  // console.log(inFile);

  worker.postMessage({ inFile, password, salt, command: 'startEncryptionStreaming'});
  // let offset = 0;
  // while (offset < inFile.size) {
  //   let chunkSize = Math.min(1024 * 512, inFile.size - offset);
  //   let currentSlice = await inFile.slice(offset, offset + chunkSize).arrayBuffer();
  //   console.log(currentSlice);
  //   console.log(`len: ${currentSlice.len}, currentSlice: ${currentSlice}`);
  //   offset += chunkSize;
  // }
}


startDecryption = async (inFile, password) => {
  inBuffer = await inFile.arrayBuffer();
  outBuffers = [];
  filename = inFile.name;
  output(`Filename: ${filename}, size: ${inBuffer.byteLength}`);
  worker.postMessage({ inBuffer, password, filename, command: c.START_DECRYPTION }, [inBuffer]); // make sure to transfer inBuffer, not clone
}

const output = (msg) => {
  if (window.getComputedStyle(outputBox).display === 'none') {
    outputBox.style = 'display: unset';
  }
  let message = document.createElement('span');
  message.textContent = msg;
  outputBox.appendChild(message);
  outputBox.appendChild(document.createElement('br'));
}

const updateProgress = (msg) => {
  if (window.getComputedStyle(progressBar).display === 'none') {
    progressBar.style = 'display: unset';
  }
  if (!(typeof msg === 'number')) {
    msg = 100; // if empty file, we divided by 0 in worker, so msg will be NaN
  }
  progressBar.value = msg;
}

const compareArrays = (a1, a2) => {
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}

const extensionIsCloaker = (filename) => {
  return filename.length > c.EXTENSION.length
    && filename.slice(filename.length - c.EXTENSION.length, filename.length) === c.EXTENSION;
}

const getDecryptFilename = (filename) => {
  // if filename is longer than .cloaker and ends with .cloaker, chop off extension. if not, leave as is and let the user or OS decide.
  let suffixes = [c.EXTENSION, c.EXTENSION + '.txt']; // Chrome on Android adds .cloaker.txt for some reason
  let decryptFilename = filename;
  for (let i in suffixes) {
    let len = suffixes[i].length;
    if (filename.length > len && filename.slice(filename.length - len, filename.length) === suffixes[i]) {
      decryptFilename = filename.slice(0, filename.length - len);
    }
  }
  return decryptFilename;
}

// things that need to change:
// hand infile instead of inbuffer to worker
// write to file instead of outbuffer
// select file before starting
// no download button

// new flow?
// 1. select input file
// 2. display encrypt/decrypt button
// 3. prefill output file

// check that file is selected before starting
// set file to undefined at finish
