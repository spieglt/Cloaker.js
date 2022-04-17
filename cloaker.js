import * as c from './constants.js';

let inFile;
let outFile;
let outHandle;
let outStream;
let startEncryption;
let startDecryption;
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
let streaming = !!window.showSaveFilePicker;

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
    output(`File to ${decrypting ? "decrypt" : "encrypt"}: ${inFile.name}, size `);
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
    outHandle = await window.showSaveFilePicker({
      suggestedName: inFile.name + c.EXTENSION,
      types: [{
        description: 'Cloaker',
        accept: {'application/cloaker': [c.EXTENSION]},
      }],
    });
    outFile = await outHandle.getFile();
    outStream = await outHandle.createWritable();
    // output(`Output filename: ${outFile.name}`);
    startEncryption(inFile, password);
  };

  decryptButton.onclick = async () => {
    if (!inFile) {
      output('Please select file.');
    }
    const password = passwordBox.value;
    outHandle = await window.showSaveFilePicker({
      suggestedName: getDecryptFilename(inFile.name),
    });
    outFile = await outHandle.getFile();
    outStream = await outHandle.createWritable();
    // output(`Output filename: ${outFile.name}`);
    startDecryption(inFile, password);
  };
};

let worker = new Worker('./worker.js');

worker.onmessage = (message) => {
  // console.log('main received:', message);
  switch (message.data.response) {
    case c.INITIALIZED_ENCRYPTION:
      outStream.write(message.data.header);
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // kick off actual encryption
      break;
    case c.ENCRYPTED_CHUNK:
      outStream.write(message.data.encryptedChunk);
      updateProgress(message.data.progress);
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // next chunk
      break;
    case c.FINAL_ENCRYPTION:
      outStream.write(message.data.encryptedChunk);
      outStream.close();
      updateProgress(message.data.progress);
      output(`Encryption of ${outFile.name} complete.`);
      break;
    case c.INITIALIZED_DECRYPTION:
      worker.postMessage({ command: c.DECRYPT_CHUNK }); // kick off decryption
      break;
    case c.DECRYPTED_CHUNK:
      outStream.write(message.data.decryptedChunk);
      updateProgress(message.data.progress);
      worker.postMessage({ command: c.DECRYPT_CHUNK });
      break;
    case c.FINAL_DECRYPTION:
      outStream.write(message.data.decryptedChunk);
      outStream.close();
      updateProgress(message.data.progress);
      output(`Decryption of ${outFile.name} complete.`);
      break;
    case c.DECRYPTION_FAILED:
      output('Incorrect password');
      break;
  }
};

startEncryption = async (inFile, password) => {
  outStream.write(c.SIGNATURE);
  output(`Filename: ${inFile.name}, size: ${inFile.size}`);
  let salt = new Uint8Array(c.crypto_pwhash_argon2id_SALTBYTES);
  window.crypto.getRandomValues(salt);
  outStream.write(salt);
  worker.postMessage({ inFile, password, salt, command: c.START_ENCRYPTION });
}

startDecryption = async (inFile, password) => {
  output(`Filename: ${inFile.name}, size: ${inFile.size}`);
  worker.postMessage({ inFile, password, command: c.START_DECRYPTION });
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
    console.log(typeof msg, msg);
  }
  progressBar.value = msg;
}

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
// how to prompt user that they need to select output file? print "encrypting file x" after select file and then prompt again when clicking decrypt button

// new flow?
// 1. select input file
// 2. display encrypt/decrypt button
// 3. prefill output file

// check that file is selected before starting
// set file to undefined at finish

// Test: new files, old files, legacy files, empty files, chrome, firefox, mobile

// show speed
// show kb/mb/gb
// to add firefox back in, don't have to worry about input, new streaming input is better. just need to add different output behavior, click different button? 
