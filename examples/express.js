var express = require('express');
var fs = require('fs');
var os = require('os');
var path = require('path');
var https = require('https');
const clientCertificateAuth = require('../index.js').clientCertificateAuth

// Default key dir is cwd for example only!
process.env.PKIDIR = process.env.PKIDIR || process.cwd()

async function getOptions (options) {
  options = options || {}
  if (Object.keys(options).length === 0) {
    options.allowHTTP1 = process.env.ALLOW_HTTP1 || true
    options.maxVersion = 'TLSv1.2'
    options.ca = await fs.promises.readFile(path.join(process.env.PKIDIR, 'fullchain.pem'))
    options.key = await fs.promises.readFile(path.join(process.env.PKIDIR, 'privkey.pem'))
    options.cert = await fs.promises.readFile(path.join(process.env.PKIDIR, 'cert.pem'))
    options.requestCert = true
    options.rejectUnauthorized = true
  }
  return options
}

var app = express();

// add clientCertificateAuth to the middleware stack, passing it a callback
// which will do further examination of the provided certificate.

//app.use(clientCertificateAuth(getOptions, () => true));

app.get('/unsecure', function(req, res) {
  res.send('Hello world');
});

app.get('/secure', clientCertificateAuth(getOptions, () => true), function(req, res) {
  res.send('Hello authorized user');
});

getOptions().then(opts => {
  https.createServer(opts, app).listen(4000);
})


