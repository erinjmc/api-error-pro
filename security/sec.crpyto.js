let crypto = require('crypto');
let sha256 = require('crypto-js/sha256');
let base64url = require('base64url');
let secret = sha256('8be17f70-0f19-47a3-9db3-87bc20d97d8a').toString();
let uuid = require('uuid');

function getSaltedPassword(pwd) {
    let salt = crypto.randomBytes(256).toString('hex');
    let hashedPassword = crypto.pbkdf2Sync(pwd, salt, 100000, 512, 'sha512').toString('hex');
    return hashedPassword + '*' + salt;
}

function createSignature(stringToHash) {
    return sha256(stringToHash, secret).toString();
}

function buildToken(user) {
    let header = { 
        typ: 'JWT',
        alg: 'HS256'
    }
    let payload = {
        id: uuid.v4(),
        iat: Date.now(),
        username: user.username,
        claims: user.claims
    }

    let stringToHash = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload));
    let token = { id: payload.id, iat: payload.iat , issuedTo: payload.username, key: stringToHash + '.' + createSignature(stringToHash) };
    user.tokens.push({id: token.id, iat: token.iat});
    return { user: user, token: token };
}

function validatePassword(password, user) {
    let usrHashedPwd = user.saltedPassword.split('*')[0];
    let salt = user.saltedPassword.split('*')[1];
    let comparison = crypto.pbkdf2Sync(password, salt, 100000, 512, 'sha512').toString('hex');
    
    if( usrHashedPwd === comparison ){
        let tokenCtn = buildToken(user);
        return  {  error: false, errorMsg: null, token: tokenCtn.token } ;
    }

    return  { error: true, errorMsg: 'Incorrect Password'} ;
}

function validateToken(_token) {
    let result = { error: true, errorMsg: 'Invalid token (0)', data: null } ;
    if(_token.length >= 7) {
        let token = _token.substr(7);
        if( token !== null || typeof token !== 'undefined' || token !== '') {
            let forSignature = token.split('.')[0] + '.' + token.split('.')[1];
            let signature = token.split('.')[2];
            let compare = createSignature(forSignature);
            result.error = !(signature === compare);
            if(result.error){
                result.errorMsg ='Invalid token (1)';
            }
            else {
                result.errorMsg = null;
            }
            
            return  result;
        }
    }
    return  result;
}


module.exports.cryptography = { getSaltedPassword: getSaltedPassword, validatePassword: validatePassword, getToken: buildToken, validateToken: validateToken }