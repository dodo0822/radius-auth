var express = require('express');
var bodyParser = require('body-parser');
var morgan = require('morgan');
var radius = require('radius');
var dgram = require('dgram');
var hat = require('hat');
var mongoose = require('mongoose');
var db = require('./db');
var util = require('./util');
var portPool = require('./port-pool');
var config = require('./config');

portPool.initialize();

mongoose.connect('mongodb://localhost/radius');

var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
// app.use(morgan('combined'));
app.use('/static', express.static(__dirname + '/static'));
app.use('/bower_components', express.static(__dirname + '/bower_components'));
app.set('view engine', 'ejs');
app.disable('x-powered-by');

app.get('/ping', function(req, res){
	res.send('Pong');
});

app.get('/login', function(req, res){
	var vals = {
		gw_address: req.query.gw_address,
		gw_port: req.query.gw_port
	};
	if(req.query['msg'] === 'denied') vals['msg'] = '使用者名稱或密碼錯誤。';
	if(req.query['msg'] === 'blank')  vals['msg'] = '所有欄位皆必須填寫！';
	res.render('login', vals);
});

app.post('/validate', function(req, res){
	if(!(req.body.username && req.body.password)){
		res.redirect('/login?gw_address=' + req.body.gw_address + '&gw_port=' + req.body.gw_port + '&msg=blank');
		return;
	}
	
	if(!config.test){
		var packet = {
			code: 'Access-Request',
			secret: config.secret,
			identifier: 0,
			attributes: [
				[ 'User-Name', req.body.username ],
				[ 'User-Password', req.body.password ]
			]
		};

		var client = dgram.createSocket('udp4');
		var bind_port = portPool.request();
		var sent_packet = null;

		client.bind(bind_port);
		client.on('message', function(msg, rinfo){
			var response = radius.decode({ packet: msg, secret: config.secret });
			var valid_response = radius.verify_response({
				response: msg,
				request: sent_packet.raw_packet,
				secret: sent_packet.secret
			});
			var ip = req.ip;
			if(valid_response){
				var token = hat();
				if(response.code !== 'Access-Accept'){
					res.redirect('/login?gw_address=' + req.body.gw_address + '&gw_port=' + req.body.gw_port + '&msg=denied');
				} else {
					console.log('[login] User ' + req.body.username + ' successfully logged in');
					var tokObj = new db.Token({
						token: token,
						ip: req.ip,
						username: req.body.username,
						time: new Date()
					});
					tokObj.save(function(err){
						res.redirect('http://' + req.body.gw_address + ':' + req.body.gw_port + '/wifidog/auth?token=' + token);
					});
				}
			} else {
				res.send('500 Internal Server Error', 500);
				console.log('[login] Invalid RADIUS response received');
			}
			client.close();
			portPool.free(bind_port);
		});
		var encoded = radius.encode(packet);
		sent_packet = {
			raw_packet: encoded,
			secret: packet.secret
		};
		client.send(encoded, 0, encoded.length, config.port, config.host);
	} else {
		var token = hat();
		console.log('[login] User ' + req.body.username + ' successfully logged in');
		var tokObj = new db.Token({
			token: token,
			ip: req.ip,
			username: req.body.username,
			time: new Date()
		});
		tokObj.save(function(err){
			res.send('OK, token: ' + token);
		});
	}
});

app.get('/auth', function(req, res){
	if(req.query.stage === 'counters'){
		res.send('Auth: 1');
		return;
	}
	db.Token.findOne({ token: req.query.token }, function(err, token){
		if(!token){
			res.send('Auth: 0');
		} else {
			if(token.ip === req.query.ip){
				token.mac = req.query.mac;
				token.save(function(err){
					res.send('Auth: 1');
					console.log('[auth] ' + req.query.ip + ' authenticate success');
				});
			} else {
				res.send('Auth: 0');
				console.log('[auth] ' + req.query.ip + ' authenticate failure');
				console.log('[auth]   |- MAC  : ' + req.query.mac);
				console.log('[auth]   |- token: ' + req.query.token);
			}
		}
	});
});

app.get('/portal', function(req, res){
	res.redirect('http://www.hs.ntnu.edu.tw/');
});

app.get('/manage/login', function(req, res){
	res.render('manage_login');
});

app.use(function(req, res){
	res.send('Not found.', 404);
});

var server = app.listen(3000, function() {
	console.log('Listening on port %d', server.address().port);
});
