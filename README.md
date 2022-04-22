# Cloaker.mobi

**Please visit https://cloaker.mobi to encrypt/decrypt files!**

## FAQ

**Q:** What is this and why is it here?

**A:** It's an easy way to encrypt a file with a password and decrypt it later. I wrote the <a href='https://cloaker.spiegl.dev/'>desktop version</a> out of frustration that there was no simple, portable, safe way to protect a file with a password. I wanted to make a mobile version but writing apps was a hassle and distributing this as a small static website is much more pleasant than paying Apple $100/year for a developer account and dealing with app stores. This version is interoperable with the desktop version.

--------------------

**Q:** How do I encrypt multiple files under the same password?

**A:** Put them in a `.zip` first then encrypt that. <a href='https://support.apple.com/en-us/HT211132'>iOS</a> does this natively, but for Android you'll need a third-party app.

--------------------

**Q:** What happens to my data?

**A:** Nothing you encrypt or decrypt with Cloaker is sent anywhere. Everything is done on your device, by your browser, with JavaScript and WebAssembly. This page is just static HTML/CSS/JS served by GitHub, so they likely collect some metadata about visits (see their <a href='https://docs.github.com/en/github/site-policy/github-privacy-statement'>privacy policy</a>), but I do not.

--------------------

**Q:** Did you write the crypto, you fool? Where's the code?

**A:** No, Cloaker just uses the `pwhash` and `secretstream` APIs from <a href='https://github.com/jedisct1/libsodium.js/'>libsodium.js</a>. Code is <a href='https://github.com/spieglt/Cloaker.js'>here</a>.

--------------------

**Q:** How large of a file can I encrypt/decrypt?

**A:** If you don't use the desktop version of Chrome, it depends on how much RAM is in your device. In browsers without <a href='https://developer.mozilla.org/en-US/docs/Web/API/FileSystemWritableFileStream#browser_compatibility'>FileSystemWritableFileStream</a>, Cloaker has to keep the encrypted or decrypted file in memory in until you save it and navigate away from the page, so it does not work for large files on phones. If you have a computer, you can use <a href='https://cloaker.spiegl.dev/'>the desktop version of Cloaker</a> which is faster, handles arbitrarily large files, and has cross-platform GUI and CLI versions. On the desktop version of Chrome, however, you can encrypt and decrypt arbitrarily large files as the output will stream to your filesystem.

--------------------
**Q:** How does it encrypt/decrypt in a long-running operation without interrupting the UI?

**A:** <a href='https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API'>Web workers!</a>
