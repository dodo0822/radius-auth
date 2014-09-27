var crypto = require('crypto');

module.exports = {
	hash: function(str){
		var sha256 = crypto.createHash('sha256');
		sha256.update(str, 'utf8');
		var result = sha256.digest('base64');
		return result;
	}
};