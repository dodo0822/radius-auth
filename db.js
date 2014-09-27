var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var Token = new Schema({
	token: String,
	ip: String,
	mac: String,
	username: String,
	time: Date
});

var User = new Schema({
	username: String,
	password: String,
	lastLogin: Date,
	lastLoginIp: String
});

var tok = mongoose.model('Token', Token);
var usr = mongoose.model('User', User);

module.exports.Token = tok;
module.exports.User = usr;