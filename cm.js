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
let passwordBox;
let outputBox;

window.onload = () => {
  encryptButton = document.getElementById('encryptButton');
  encryptElem = document.getElementById('encryptElem');
  decryptButton = document.getElementById('decryptButton');
  decryptElem = document.getElementById('decryptElem');
  passwordBox = document.getElementById('passwordBox');
  outputBox = document.getElementById('outputBox');

  encryptButton.addEventListener('click', (e) => {
    encryptElem.click();
  }, false);

  encryptElem.onchange = async (e) => {
    const password = passwordBox.value;
    // if (password.length < 12) {
    //   alert('Password must be at least 12 characters. 16 or more is recommended.');
    //   return;
    // }
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


let filename, inBuffer, outBuffers, outFile, downloadLink;
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
      replace(message.data.progress);
      worker.postMessage({ command: 'encryptChunk' }); // next chunk
      break;
    case 'finalEncryption':
      outBuffers.push(message.data.encryptedChunk);
      replace(message.data.progress);
      outFile = new File(outBuffers, filename + '.cloaker');
      output('\ndone\n');
      downloadLink = document.getElementById('downloadLink');
      downloadLink.download = filename + '.cloaker';
      downloadLink.style = '';
      downloadLink.href = URL.createObjectURL(outFile);
      break;
    case 'initializedDecryption':
      worker.postMessage({ command: 'decryptChunk' }); // kick off decryption
      break;
    case 'decryptedChunk':
      outBuffers.push(message.data.decryptedChunk);
      replace(message.data.progress);
      worker.postMessage({ command: 'decryptChunk' });
      break;
    case 'finalDecryption':
      outBuffers.push(message.data.decryptedChunk);
      replace(message.data.progress);
      // if filename is longer than .cloaker and ends with .cloaker, chop off extension. if not, leave as is and let the user or OS decide.
      let suffixes = ['.cloaker', '.cloaker.txt']; // Chrome on Android adds .cloaker.txt for some reason
      let outputFilename = filename;
      for (i in suffixes) {
        let len = suffixes[i].length;
        if (filename.length > len && filename.slice(filename.length - len, filename.length) === suffixes[i]) {
          outputFilename = filename.slice(0, filename.length - len);
        }
      }
      outFile = new File(outBuffers, outputFilename);
      output('\ndone\n');
      downloadLink = document.getElementById('downloadLink');
      downloadLink.download = outputFilename;
      downloadLink.style = '';
      downloadLink.href = URL.createObjectURL(outFile);
      break;
    case 'decryptionFailed':
      output('incorrect password\n');
      break;
    case 'notCloaker':
      output('file was not encrypted with cloaker\n');
      break;
  }
};

startEncryption = async (inFile, password) => {
  inBuffer = await inFile.arrayBuffer();
  outBuffers = [new Uint8Array(SIGNATURE)];
  filename = inFile.name;
  output(`filename: ${filename}, size: ${inBuffer.byteLength}\n`);
  let salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);
  window.crypto.getRandomValues(salt);
  outBuffers.push(salt);
  worker.postMessage({ inBuffer, password, salt, command: 'startEncryption' }, [inBuffer]); // make sure to transfer inBuffer, not clone
}

startDecryption = async (inFile, password) => {
  inBuffer = await inFile.arrayBuffer();
  outBuffers = [];
  filename = inFile.name;
  output(`filename: ${filename}, size: ${inBuffer.byteLength}\n`);
  worker.postMessage({ inBuffer, password, filename, command: 'startDecryption' }, [inBuffer]); // make sure to transfer inBuffer, not clone
}

const output = (msg) => {
  line = output.value === undefined ? '' : '\n';
  outputBox.value = outputBox.value + line + msg;
}

const replace = (msg) => {
  outputBox.value = outputBox.value.slice(0, outputBox.value.lastIndexOf('\n')) + '\n' + msg;
}

/*
TODO:
typescript
large file testing
vector graphic logo
*/
