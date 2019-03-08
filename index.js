// Based on work from https://github.com/jsonwebtoken/jsonwebtoken.github.io
require('dotenv').config();

const secret = process.env.JWT_SECRET

const jose= require('node-jose');
const b64u= require('base64url');
const pAny = require('p-any');
const { pki } = require('node-forge');

const log  = require('loglevel');
log.setLevel("trace");
// node-jose does not support keys shorter than block size. This is a
// limitation from their implementation and could be resolved in the future.
// See: https://github.com/cisco/node-jose/blob/master/lib/jwk/octkey.js#L141
function paddedKey(key, alg, base64Secret) {
  const blockSizeBytes = alg.indexOf('256') !== -1 ? 512 / 8 : 1024 / 8;

  let buf = base64Secret ? Buffer.from(key, 'base64') : Buffer.from(key);

  if(buf.length < blockSizeBytes) {
    const oldBuf = buf;
    buf = Buffer.alloc(blockSizeBytes);
    buf.set(oldBuf);
  }

  return b64u.encode(buf);
}

/*
 * This function handles plain RSA keys not wrapped in a
 * X.509 SubjectPublicKeyInfo structure. It returns a PEM encoded public key
 * wrapper in that structure.
 * See: https://stackoverflow.com/questions/18039401/how-can-i-transform-between-the-two-styles-of-public-key-format-one-begin-rsa
 * @param {String} publicKey The public key as a PEM string.
 * @returns {String} The PEM encoded public key in
 *                   X509 SubjectPublicKeyInfo format.
 */
function plainRsaKeyToX509Key(key) {
  try {
    const startTag = '-----BEGIN RSA PUBLIC KEY-----';
    const endTag = '-----END RSA PUBLIC KEY-----';
    const startTagPos = key.indexOf(startTag);
    const endTagPos = key.indexOf(endTag);

    return startTagPos !== -1 && endTagPos !== -1 ?
            pki.publicKeyToPem(pki.publicKeyFromPem(key)) :
            key;
  } catch(e) {
    // If anything fails, it may not be a plain RSA key, so return the same key.
    return key;
  }
}

function getJoseKey(header, key, base64Secret) {
  if(header.alg.indexOf('HS') === 0) {
    return jose.JWK.asKey({
      kty: 'oct',
      use: 'sig',
      alg: header.alg,
      k: paddedKey(key, header.alg, base64Secret)
    });
  } else {
    if(header.alg.indexOf('RS') === 0) {
      key = plainRsaKeyToX509Key(key);
    }

    return pAny(['pem', 'json'].map(form => {
      try {
        return jose.JWK.asKey(key, form);
      } catch(e) {
        return Promise.reject(e);
      }
    }));
  }
}
/* unused
function sign(header,
                     payload,
                     secretOrPrivateKeyString,
                     base64Secret = false) {
  if(!header.alg) {
    return Promise.reject(new Error('Missing "alg" claim in header'));
  }

  return getJoseKey(header, secretOrPrivateKeyString, base64Secret).then(
    key => {
      if(!(typeof payload === 'string' || payload instanceof String)) {
        payload = JSON.stringify(payload);
      }

      return jose.JWS.createSign({
        fields: header,
        format: 'compact'
      }, {
        key: key,
        reference: false
      }).update(payload, 'utf8').final();
    }
  );
}
*/
function verify(jwt, secretOrPublicKeyString, base64Secret = false) {
  if(!isToken(jwt)) {
    return Promise.resolve(false);
  }

  const decoded = decode(jwt);

  if(!decoded.header.alg) {
    return Promise.resolve(false);
  }

  return getJoseKey(decoded.header, secretOrPublicKeyString, base64Secret).then(
    key => {
      return jose.JWS.createVerify(key)
                     .verify(jwt)
                     .then(() => true, () => false);
    }, e => {
      log.warn('Could not verify token, ' +
               'probably due to bad data in it or the keys: ', e);
      return false;
    }
  );
}

function decode(jwt) {
  const result = {
    header: {},
    payload: {},
    errors: false
  };

  if(!jwt) {
    result.errors = true;
    return result;
  }

  const split = jwt.split('.');

  try {
    result.header = JSON.parse(b64u.decode(split[0]));
  } catch(e) {
    result.header = {};
    result.errors = true;
  }

  try {
    result.payload = JSON.parse(b64u.decode(split[1]));
  } catch(e) {
    result.payload = {};
    result.errors = true;
  }

  return result;
}

function isValidBase64String(s, urlOnly) {
  try {
    const validChars = urlOnly ?
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' :
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/=';

    let hasPadding = false;
    for(let i = 0; i < s.length; ++i) {
      hasPadding |= s.charAt(i) === '=';
      if(validChars.indexOf(s.charAt(i)) === -1) {
        return false;
      }
    }

    if(hasPadding) {
      for(let i = s.indexOf('='); i < s.length; ++i) {
        if(s.charAt(i) !== '=') {
          return false;
        }
      }

      return s.length % 4 === 0;
    }

    return true;
  } catch (e) {
    return false;
  }
}

function isToken(jwt, checkTypClaim = false) {
  const decoded = decode(jwt);

  if(decoded.errors) {
    return false;
  }

  if(checkTypClaim && decoded.header.typ !== 'JWT') {
    return false;
  }

  const split = jwt.split('.');
  let valid = true;
  split.forEach(s => valid = valid && isValidBase64String(s, true));

  return valid;
}
/* uncomment for testing
let secret_obj={
  "kid":"THISISTHE-KEYCLOAK-KEY-ID",
  "kty":"RSA",
  "alg":"RS256",
  "use":"sig",
  "n":"verylongstringofasciicharacters",
  "e":"ashortstring"
  };

let string_secret = JSON.stringify(secret_obj);

// use "string_secret" in place of "secter" for testing
*/
exports.handler = function(event, context) {
  // console.log("secret", secret);
  if(event.authorizationToken && event.authorizationToken.split(' ')[0] === 'Bearer') {
    // console.log("secretBuf", secretBuf);
    var idToken = event.authorizationToken.split(' ')[1];

    verify(idToken, secret).then(valid => {
      if(valid) {
        log.info("verified");
        const decoded = decode(idToken);
        log.info('authorized:', decoded);

        return context.succeed(generatePolicy(decoded.payload.sub, 'Allow', event.methodArn));
      } else {
        log.warn("invalid token, not authorized");
        return context.fail('invalid token, not authorized');
      }
    });
  } else {
    log.warn('invalid authorization token or header', event.authorizationToken);
    return context.fail('invalid authorization token or header');
  }
};

var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; // default version
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; // default action
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
};


/*
 // Uncomment to test the handler locally
let event = {};
event.methodArn = "arn:aws:execute-api:<Region id>:<Account id>:<API id>/<Stage>/<Method>/<Resource path>";
event.authorizationToken = "Bearer TYPE-THE-TOKEN-HERE";

let context = {
  fail: function(message){
    log.warn("--- FAIL ---");
    log.warn(message);
    log.warn("--- FAIL ---");
  },
  succeed: function(message){
    log.info("+++ SUCCESS +++");
    log.info(message);
    log.info("+++ SUCCESS +++");
  }
}

handler(event, context);

*/
