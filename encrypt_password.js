'use strict';
var crypto = require('crypto');
/**
* generates random string of characters i.e salt
* @function
* @param {number} length - Length of the random string.
*/
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
     .toString('hex') /** convert to hexadecimal format */
     .slice(0,length); /** return required number of characters */
};
/**
* hash password with sha512.
* @function
* @param {string} password - List of required fields.
* @param {string} salt - Data to be validated.
*/
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('base64');
    return {
        salt:salt,
        passwordHash:value
    };
};

exports.saltHashPassword = function(userpassword) {
    try {
        var salt = genRandomString(16);
        var passwordData = sha512(userpassword, salt);
        
        passwordData = passwordData.passwordHash + "$" + passwordData.salt
        return passwordData;
    }catch (e) {
        return "";
    }
}

exports.compareHashPassword = function(userpassword, hashsaltpassword){
    try {
        var pass = hashsaltpassword.split("$");
        let salt = pass[1];
        let hash = crypto.createHmac('sha512', salt).update(userpassword).digest("base64");
        if (hash === pass[0]){
            return true;
        }else{
            //console.log('Password tidak cocok!');
            return false;
        }
    }catch (e) {
        return false;
    }
}
