/*!
 * client-certificate-auth - node.js Connect/Express middleware to perform
 *   authentication based on a client SSL certificate
 * Copyright (C) 2013 Tony Gies
 */

/** 
 * Enforce SSL client authorization and provide a `callback(cert)` which will
 * be passed the client certificate information (as obtained through
 * `req.connection.getPeerCertificate()`) for additional validation, e.g. to
 * check it against a whitelist. `callback(cert)` must return `true` for the
 * request to proceed.
 *
 * If certificate fails check, try to renegotiate TLS session, so that
 * client ceritificate selection dialog is kicked off by the browser.
 * (TLS 1.3 not supported)
 *
 * @param {AsyncFunction} getOptions Gets a TLS configuration object for 
 *                        renegotiating a secure session.
 * @param {Function} callback
 */

export function clientCertificateAuth(getOptions, callback) {
  return function middleware(req, res, next) {
    // Try to do an SSL redirect if this doesn't look like an SSL request.
    // The weird header check is necessary for this to work on Heroku.
    //
    // This does not belong here! Should be separate function/middleware.
    // - isysd
    //
    //if (!req.secure && req.header('x-forwarded-proto') != 'https') {
    //  return res.redirect('https://' + req.header('host') + req.url);
    //}

    // Obtain certificate details
    var cert = req.connection.getPeerCertificate(true);
    if (!cert || !Object.keys(cert).length) {
      if (getOptions) {
        // renegotiate client certificate
        // not TLSv1.3 compatible
        getOptions().then(opts => {
          if (req.connection.renegotiate) req.connection.renegotiate(opts, checkCertAuth)
          else {
            // could not renegotiate, so return Unauthorized
            var e = new Error('Client certificate is required.');
            e.status = 401;
            return next(e);
          }
        }).catch(next)
      } else {
        // could not renegotiate, so return Unauthorized
        var e = new Error('Client certificate is required.');
        e.status = 401;
        return next(e);
      }
    } else checkCertAuth()

    function checkCertAuth (e) {
      if (e) next(e);
      else {
        // Ensure that the certificate was validated at the protocol level
        var sock = req.connection || req.client || undefined
        if (!sock || !sock.authorized) {
          var err = sock && sock.authorizationError ? sock.authorizationError : ''
          var e = new Error('Unauthorized: Client certificate required ' + err);
          e.status = 401;
          return next(e);
        } else {
          // Fire the callback. If it returns true, the request may proceed. If it
          // returns false, bail out with a 401 Unauthorized.
          if (callback && callback.length === 2) {
            callback(cert, doneAuthorizing);
          } else if (callback) {
            doneAuthorizing(callback(cert));
          } else (
            next()
          )
        }
      }
    }

    function doneAuthorizing(authorized) {
      if (authorized) {
        return next();
      } else {
        var e = new Error('Unauthorized');
        e.status = 401;
        return next(e);
      }
    }
  };
};

export default clientCertificateAuth
