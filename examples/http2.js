/*
HTTP2, no external requirements example.
*/
import * as http2 from 'http2'
import * as url from 'url'
import * as os from 'os'
import * as fs from 'fs'
import * as path from 'path'
import clientCertificateAuth from '../lib/clientCertificateAuth.js'

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

// Start an https server to call the authenticated handler
getOptions().then((options) => {
  options.rejectUnauthorized = false // set to false initially for public view
  const server = http2.createSecureServer(options, (req, res) => {
    if (req.url === '/secure') {
      clientCertificateAuth(getOptions, () => true)(req, res, (e) => {
        if (e) {
          console.error(e)
          res.writeHead(e.status || 500, e.message)
          res.end()
        } else {
          res.writeHead(200)
          res.end(`Hello authorized user: ${req.connection.getPeerCertificate(true).subject.CN}`)
        }
      })
    } else {
      res.writeHead(200)
      res.end(`Hello world`)
    }
  })

  server.listen(4000)
})

