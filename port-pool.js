module.exports = {
	pool: {},
	initialize: function(){
		for(var i = 49001; i <= 49100; ++i){
			module.exports.pool[i] = true;
		}
	},
	request: function(){
		for(var p in module.exports.pool){
			if(module.exports.pool[p] === true){
				module.exports.pool[p] = false;
				return p;
			}
		}
		console.log('[PortPool] No available port!');
		return -1;
	},
	free: function(p){
		module.exports.pool[p] = true;
		return;
	}
};

