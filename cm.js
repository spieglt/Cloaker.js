const crypto_pwhash_argon2id_SALTBYTES = 16;
const SIGNATURE = new Uint8Array([0xC1, 0x0A, 0x6B, 0xED]);

let startEncryption;
let encryptChunk;
let startDecryption;
let decryptChunk;
let encryptButton;
let encryptElem;
let decryptButton;
let decryptElem;
let passwordTitle;
let passwordBox;
let outputBox;
let progressBar;

window.onload = () => {
  encryptButton = document.getElementById('encryptButton');
  encryptElem = document.getElementById('encryptElem');
  decryptButton = document.getElementById('decryptButton');
  decryptElem = document.getElementById('decryptElem');
  passwordTitle = document.getElementById('passwordTitle');
  passwordBox = document.getElementById('passwordBox');
  outputBox = document.getElementById('outputBox');
  progressBar = document.getElementById('progressBar');

  encryptButton.addEventListener('click', (e) => {
    encryptElem.click();
  }, false);

  encryptElem.oninput = async (e) => {
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
    startEncryption(encryptElem.files[0], password);
  };

  decryptButton.addEventListener('click', (e) => {
    decryptElem.click();
  }, false);

  decryptElem.onchange = async (e) => {
    const password = passwordBox.value;
    startDecryption(decryptElem.files[0], password);
  };
};


let filename, inBuffer, outBuffers, outputFilename, outFile, downloadLink;
let worker = new Worker('./worker.js');

worker.onmessage = (message) => {
  // console.log('main received:', message);
  switch (message.data.response) {
    case 'initializedEncryption':
      outBuffers.push(message.data.header);
      worker.postMessage({ command: 'encryptChunk' }); // kick off actual encryption
      break;
    case 'encryptedChunk':
      outBuffers.push(message.data.encryptedChunk);
      updateProgress(message.data.progress);
      worker.postMessage({ command: 'encryptChunk' }); // next chunk
      break;
    case 'finalEncryption':
      outBuffers.push(message.data.encryptedChunk);
      updateProgress(message.data.progress);
      outputFilename = filename + '.cloaker';
      outFile = new File(outBuffers, outputFilename);
      downloadLink = document.getElementById('downloadLink');
      downloadLink.download = filename + '.cloaker';
      downloadLink.href = URL.createObjectURL(outFile);
      downloadLink.innerText = `Download encrypted file "${outputFilename}"`
      downloadLink.style = 'display: unset';
      break;
    case 'initializedDecryption':
      worker.postMessage({ command: 'decryptChunk' }); // kick off decryption
      break;
    case 'decryptedChunk':
      outBuffers.push(message.data.decryptedChunk);
      updateProgress(message.data.progress);
      worker.postMessage({ command: 'decryptChunk' });
      break;
    case 'finalDecryption':
      outBuffers.push(message.data.decryptedChunk);
      updateProgress(message.data.progress);
      // if filename is longer than .cloaker and ends with .cloaker, chop off extension. if not, leave as is and let the user or OS decide.
      let suffixes = ['.cloaker', '.cloaker.txt']; // Chrome on Android adds .cloaker.txt for some reason
      outputFilename = filename;
      for (i in suffixes) {
        let len = suffixes[i].length;
        if (filename.length > len && filename.slice(filename.length - len, filename.length) === suffixes[i]) {
          outputFilename = filename.slice(0, filename.length - len);
        }
      }
      outFile = new File(outBuffers, outputFilename);
      downloadLink = document.getElementById('downloadLink');
      downloadLink.download = outputFilename;
      downloadLink.href = URL.createObjectURL(outFile);
      downloadLink.innerText = `Download decrypted file "${outputFilename}"`
      downloadLink.style = 'display: unset';
      break;
    case 'decryptionFailed':
      output('incorrect password');
      break;
    case 'notCloaker':
      output('file was not encrypted with cloaker');
      break;
  }
};

startEncryption = async (inFile, password) => {
  inBuffer = await inFile.arrayBuffer();
  outBuffers = [new Uint8Array(SIGNATURE)];
  filename = inFile.name;
  output(`Filename: ${filename}, size: ${inBuffer.byteLength}`);
  let salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);
  window.crypto.getRandomValues(salt);
  outBuffers.push(salt);
  worker.postMessage({ inBuffer, password, salt, command: 'startEncryption' }, [inBuffer]); // make sure to transfer inBuffer, not clone
}

startDecryption = async (inFile, password) => {
  inBuffer = await inFile.arrayBuffer();
  outBuffers = [];
  filename = inFile.name;
  output(`Filename: ${filename}, size: ${inBuffer.byteLength}`);
  worker.postMessage({ inBuffer, password, filename, command: 'startDecryption' }, [inBuffer]); // make sure to transfer inBuffer, not clone
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
