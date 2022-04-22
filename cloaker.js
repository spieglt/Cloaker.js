import * as c from './constants.js';

let inFile;

// check for FileSystem API
let streaming = !!window.showSaveFilePicker;
// used when streaming
let outFile;
let outHandle;
let outStream;
// used when not streaming
let outBuffers;
// writes encrypted/decrypted data to stream or the buffer to be downloaded
let writeData;

// these set up output and kick off worker.js
let startEncryption;
let startDecryption;

let selectFileButton = document.getElementById('selectFileButton');
let selectFileElem = document.getElementById('selectFileElem');
let encryptButton = document.getElementById('encryptButton');
let encryptElem = document.getElementById('encryptElem');
let decryptButton = document.getElementById('decryptButton');
let decryptElem = document.getElementById('decryptElem');
let passwordTitle = document.getElementById('passwordTitle');
let passwordBox = document.getElementById('passwordBox');
let outputBox = document.getElementById('outputBox');
let progressBar = document.getElementById('progressBar');
let speedSpan = document.getElementById('speed');
let streamingSpan = document.getElementById('streamingSpan');
let nonStreamingSpan = document.getElementById('nonStreamingSpan');

let startTime;
let progress;
let speed;
let progressInterval;

window.onload = () => {

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
    output(`File to ${decrypting ? "decrypt" : "encrypt"}: ${inFile.name}, size: ${getHumanReadableFileSize(inFile.size)}`);
  }

  encryptButton.onclick = async () => {
    if (!inFile) {
      output('Please select file.');
      return;
    }
    // check password
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
    // set up file output
    let name = inFile.name + c.EXTENSION;
    if (streaming) {
      outHandle = await window.showSaveFilePicker({
        suggestedName: name,
        types: [{
          description: 'Cloaker',
          accept: {'application/cloaker': [c.EXTENSION]},
        }],
      });
      outFile = await outHandle.getFile();
      outStream = await outHandle.createWritable();
      name = outFile.name; // use whatever name user picked
    }
    output(`Output filename: ${name}`);
    startEncryption(inFile, password);
  };

  decryptButton.onclick = async () => {
    if (!inFile) {
      output('Please select file.');
      return;
    }
    const password = passwordBox.value;
    let name = getDecryptFilename(inFile.name);
    if (streaming) {
      outHandle = await window.showSaveFilePicker({
        suggestedName: getDecryptFilename(inFile.name),
      });
      outFile = await outHandle.getFile();
      outStream = await outHandle.createWritable();
      name = outFile.name; // use whatever name user picked
    }
    output(`Output filename: ${name}`);
    startDecryption(inFile, password);
  };

  if (streaming) {
    streamingSpan.style = 'display: unset';
    nonStreamingSpan.style = 'display: none';
  } else {
    streamingSpan.style = 'display: none';
    nonStreamingSpan.style = 'display: unset';
  }
};

let worker = new Worker('./worker.js');

worker.onmessage = (message) => {
  // console.log('main received:', message);
  let bytesPerSecond, download, link, name;
  switch (message.data.response) {
    case c.INITIALIZED_ENCRYPTION:
      launchProgress();
      writeData(message.data.header);
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // kick off actual encryption
      break;
    case c.ENCRYPTED_CHUNK:
      writeData(message.data.encryptedChunk);
      bytesPerSecond = message.data.bytesWritten / ((Date.now() - startTime) / 1000);
      speed = getHumanReadableFileSize(bytesPerSecond) + '/sec';
      progress = message.data.progress;
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // next chunk
      break;
    case c.FINAL_ENCRYPTION:
      writeData(message.data.encryptedChunk);
      if (streaming) {
        name = outFile.name;
        outStream.close();
      } else {
        name = inFile.name + c.EXTENSION;
        download = new File(outBuffers, name);
        link = document.getElementById('downloadLink');
        link.download = name;
        link.href = URL.createObjectURL(download);
        link.innerText = `Download encrypted file "${name}"`
        link.style = 'display: unset';
      }
      output(`Encryption of ${name} complete.`);
      output();
      progressBar.value = message.data.progress;
      clearInterval(progressInterval);
      break;
    case c.INITIALIZED_DECRYPTION:
      launchProgress();
      worker.postMessage({ command: c.DECRYPT_CHUNK }); // kick off decryption
      break;
    case c.DECRYPTED_CHUNK:
      writeData(message.data.decryptedChunk);
      bytesPerSecond = message.data.bytesWritten / ((Date.now() - startTime) / 1000);
      speed = getHumanReadableFileSize(bytesPerSecond) + '/sec';
      progress = message.data.progress;
      worker.postMessage({ command: c.DECRYPT_CHUNK });
      break;
    case c.FINAL_DECRYPTION:
      writeData(message.data.decryptedChunk);
      if (streaming) {
        name = outFile.name;
        outStream.close();
      } else {
        name = getDecryptFilename(inFile.name);
        download = new File(outBuffers, name);
        link = document.getElementById('downloadLink');
        link.download = name;
        link.href = URL.createObjectURL(download);
        link.innerText = `Download decrypted file "${name}"`
        link.style = 'display: unset';
      }
      output(`Decryption of ${name} complete.`);
      output();
      progressBar.value = message.data.progress;
      clearInterval(progressInterval);
      break;
    case c.DECRYPTION_FAILED:
      output('Incorrect password');
      break;
  }
};

startEncryption = async (inFile, password) => {
  startTime = Date.now();
  let salt = new Uint8Array(c.crypto_pwhash_argon2id_SALTBYTES);
  window.crypto.getRandomValues(salt);
  if (streaming) {
    outStream.write(c.SIGNATURE);
    outStream.write(salt);
  } else {
    outBuffers = [new Uint8Array(c.SIGNATURE)];
    outBuffers.push(salt);
  }
  worker.postMessage({ inFile, password, salt, command: c.START_ENCRYPTION });
}

startDecryption = async (inFile, password) => {
  if (!streaming) {
    outBuffers = [];
  }
  worker.postMessage({ inFile, password, command: c.START_DECRYPTION });
}

writeData = (data) => {
  if (streaming) {
    outStream.write(data);
  } else {
    outBuffers.push(data);
  }
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

const launchProgress = () => {
  speedSpan.style = 'display: unset';
  progressBar.style = 'display: unset';
  progressInterval = setInterval( () => {
    speedSpan.textContent = 'Speed: ' + speed;
    progressBar.value = progress;
  }, 250);
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

const getHumanReadableFileSize = (size) => {
  if (size < 1000) {
    return size.toFixed(0) + ' bytes';
  } else if (size < 1000000) {
    return (size/1000).toFixed(2) + 'KB';
  } else if (size < 1000000000) {
    return (size/1000000).toFixed(2) + 'MB';
  } else if (size < 1000000000000) {
    return (size/1000000000).toFixed(2) + 'GB';
  } else {
    return (size/1000000000000).toFixed(2) + 'TB';
  }
}
