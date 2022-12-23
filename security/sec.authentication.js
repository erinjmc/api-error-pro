const cryptoModule = require('./sec.crpyto')
let uuid = require('uuid');
let ADMIN_USER_DB = [];

function getRecords(){
    return ADMIN_USER_DB;
}

function getRecord(username){
    let result = null;
    result = ADMIN_USER_DB.filter(function(entry){ 
        return entry.username === username;
    }).pop();

    return(result);
}

function newUser(creds){
    let newUsr = {
        locked: false,
        username: creds.username,
        saltedPassword: cryptoModule.cryptography.getSaltedPassword(creds.password),
        created: Date.now(),
        claims: ['user'],
        tokens: []
    };

    if(newUsr.username === 'Guest') {
        newUsr.claims.pop('user');
        newUsr.claims.push('temporary');
    }

    getRecords().push(newUsr);
    return getRecords();
}

function resetPassword(creds){
    let salt = uuid.v4();
    let user = null;

    user = getRecords().filter(function (user) {
        return user.username === creds.username;
    });

    if(user !==  null) {
        user.saltedPassword = cryptoModule.cryptography.getSaltedPassword(creds.password).concat(['*'+salt]);
    }
}

function lockAccount(username, clearTokens){
    ADMIN_USER_DB = ADMIN_USER_DB.map(function (user) {
        if(user.username ===  username) {
            user.locked = true;
            if(clearTokens) {
                user.tokens = [];
            }
        }
    });
}

function unLockAccount(username){
    ADMIN_USER_DB = ADMIN_USER_DB.map(function (user) {
        if(user.username ===  username) {
            user.locked = false;
            if(user.tokens !== null) {
                user.tokens = [];
            }
        }
    });
}

function authenticateToken(creds){
    let user = getRecord(creds.username)
    if((typeof user !== 'undefined' && user !== null && user !== '' )) {
        return cryptoModule.cryptography.validateToken(creds.token);
    } 

    return { error: true, errorMsg: 'User not found' };
}

function authenticateUsernamePassword(creds){
    let result = { error: null, errorMsg: null, data: null };
    let user = getRecord(creds.username)
    if((typeof user !== 'undefined' && user !== null && user !== '' )) {
        result = cryptoModule.cryptography.validatePassword(creds.password, user);

        if(result.error) {
            result.errorMsg = 'The token is not valid'
        } 
    }
    return result;
    
}

function logout(creds){
    let found = false;
    let temp = null;
    let user = getRecord(creds.issuedTo)
    if((typeof user !== 'undefined' || user !== null || user !== '' )) {
        temp = user.tokens.filter(function (token) {
            if(creds.id !== token.id) {
                return token;
            }
            else {
                found = true;
            }
        });

        user.tokens = temp;
        return { error: !found, errorMsg: null };
    }
    return { error: true, errorMsg: 'User not found' };

}

function validateCreds(creds, caller){
    let result = { error: null, errorMsg: null };

    if(typeof creds.username !== 'undefined' && creds.username !== null && creds.username !== '' && typeof creds.password !== 'undefined' && creds.password !== null && creds.password !== '') {
        
        let tmp = getRecord(creds.username);
        if((tmp !== null && typeof tmp !== 'undefined') && (caller === 'auth' || caller === 'reset' || caller === 'users')) {
            result.error = false;
            return result;
        }
        if((tmp !== null && typeof tmp !== 'undefined') && caller === 'new') {
            result.error = true;
            result.errorMsg = 'User already exists!';
            return result;
        }

        if((tmp === null || typeof tmp === 'undefined') && caller !== 'new') {
            result.error = true;
            result.errorMsg = 'User does not exists!';
            return result;
        }
        else {
            result.error = false;
            return result;
        }     
    }
    else{
            if(caller === 'users'){
                result.error = true;
                result.errorMsg = 'Invalid credentials';
                return result;
            }
            return { error: true, errorMsg: 'You must enter both username and password' };
    }
    
}

function validateLogout(sessionDetails){
    return typeof sessionDetails.id !== 'undefined' && sessionDetails.id !== null && sessionDetails.id !== '' && typeof sessionDetails.iat !== 'undefined' && sessionDetails.iat !== null && typeof sessionDetails.issuedTo !== 'undefined' && sessionDetails.issuedTo !== null && sessionDetails.issuedTo !== '';
}

function createDefaultLogon(){
    this.newUser({token: false, username: 'Guest', password: 'Just passing through'});
    console.log('Default user created... \n\tusername: "Guest" \n\tpassword: "Just passing through"')
}

module.exports.authModule = { 
    authenticateUsernamePassword: authenticateUsernamePassword, 
    authenticateToken: authenticateToken, 
    newUser: newUser, 
    resetPassword: resetPassword, 
    lockAccount: lockAccount, 
    unLockAccount: unLockAccount, 
    adminGetUsers: getRecords, 
    logout: logout, 
    validateCreds: validateCreds,
    validateLogout: validateLogout,
    createDefaultLogon: createDefaultLogon
};