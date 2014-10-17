var md5 = require('MD5');
var _ = require('lodash');
var crypto = require('crypto');
var deasync = require("deasync");

function getUser(req) {
	if (req.get("Authorization") || req.query.accessToken) {
		var token = req.get("Authorization") ? req.get("Authorization").split(" ")[1] : req.query.accessToken;
		try {
			var user = auth.decrypt(token, req.data._salt);
		} catch (err) {
			var user = undefined;
		}
		if (user && user.expires > (new Date()).getTime()) {
			req.user = _.find(req.data._users, function(u) {
				return u._id === user._id
			});
			if(req.user.roles.indexOf('unknown') == -1){
				req.user.roles.push("unknown");
			}
		} else {
			req.user = {
				roles: ["unknown"]
			};
		}
	} else {
		req.user = {
			roles: ["unknown"]
		};
	}
}


var auth = {
	/**
	 * This middleware makes sure that the user making a request is authorized to do so.
	 * Restrictions to paths are stored in the _acl meta object.
	 * By default every user can do anything.
	 */
	acl: function(req, res, next) {
		//Check if there is an Authorization header or the token is passed in as the GET parameter accessToken
		getUser(req);
		var acl = req.data._acl;
		var url = req.path;
		//Deny access to meta objects without 'super' group
		if (url[1] === "_" && url.indexOf("_contents") === -1 && !(url.indexOf("_users") !== -1 && req.method === "POST") && req.user.roles.indexOf("super") === -1) {
			return next({
				status: 403,
				error: "Access denied."
			});
		}
		//strip "/" character from the end of the url
		if (url[url.length - 1] === "/") url = url.substr(0, url.length - 1);

		//replace _contents with an empty string
		url = url.replace("/_contents", "");

		var foundRestriction = false; //This indicates whether there was any restriction found during the process. If not, the requests defaults to pass.
		//Loop through all possible urls starting from the beginning, eg: /, /users, /users/:id, /users/:id/comments, /users/:id/comments/:id.
		for (var i = 0; i < url.split("/").length; i++) {
			//Get the current url fragment
			var fragment = _.first(url.split("/"), (i + 1)).join("/");
			if (fragment === "") fragment = "/"; //fragment for the root element
			//Build a regex tht will be used to match urls in the _acl table
			var regex = "^";
			fragment.substr(1).split("/").forEach(function(f) {
				if (f !== "") {
					regex += "/(" + f + "|:[a-zA-Z]+)";
				}
			});
			regex += "$";
			if (regex === "^$") regex = "^/$"; //regex for the root element
			var matcher = new RegExp(regex);
			//Loop through the _acl table
			for (var key in acl) {
				if (key.match(matcher)) {
					if (acl[key][req.method]) {
						foundRestriction = true;
						//Check if the user is in a group that is inside this restriction
						if (_.intersection(req.user.roles || [], acl[key][req.method]).length > 0) {
							next();
							return;
						}

						//Check if the user is the owner of the object, when "owner" as a group is specified
						if (acl[key][req.method].indexOf("owner") > -1) {
							var node;
							var done = false;
							req.dataStore.get("/_contents" + fragment, function(err, res) {
								if (err) console.log("Error ", err);
								node = res;
								done = true;
							});
							while (!done) {
								deasync.runLoopOnce();
							}
							if (node && node._owner === req.user._id) {
								return next();
							}
						}
					}
				}
			}
		}

		//Check if we found any restrictions along the way
		if (foundRestriction) {
			return next({
				status: 403,
				error: "Access denied."
			});
		} else {
			next();
		}
	},

	userManagement: {
		signup: function(req, res, next) {
			req.targetNode = req.data._users;
			Object.defineProperty(req, 'path', {
				get: function() {
					return "/_users";
				},
				configurable: true
			});
			//Check for required password field
			if (!req.body.password) {
				return next({
					error: "Missing required field: password.",
					status: 400
				});
			}
			//Create password hash
			req.body.password = md5(req.body.password + "" + req.data._salt);
			//If it's not an array or doesn't exist, create an empty roles array
			req.body.roles = [];
			req.cantrip.post(req, res, function(err) {
				next(err);
			});
		},
		login: function(req, res, next) {
			var user = _.find(req.data._users, function(u) {
				return u._id === req.body._id
			});
			if (!user || user.password !== md5(req.body.password + "" + req.data._salt)) {
				res.status(403).send({
					"error": "Wrong _id or password."
				});
				return;
			}
			var expires = (new Date()).getTime() + 1000 * 60 * 60 * 24;
			var toCrypt = {
				_id: user._id,
				roles: user.roles,
				expires: expires
			}

			res.body = {
				token: auth.encrypt(toCrypt, req.data._salt),
				expires: expires
			};
			next();
		}
	},

	encrypt: function(obj, salt) {
		var cipher = crypto.createCipher('aes-256-cbc', salt);
		var crypted = cipher.update(JSON.stringify(obj), 'utf8', 'hex')
		crypted += cipher.final('hex');
		return crypted;
	},

	decrypt: function(string, salt) {
		var decipher = crypto.createDecipher('aes-256-cbc', salt);
		var dec = decipher.update(string, 'hex', 'utf8')
		dec += decipher.final('utf8');
		return JSON.parse(dec);
	}
}

var e = auth.acl;
e.registerMiddleware = [
	//Handle signup
	["special", "/signup", auth.userManagement.signup],
	//Don't return the password
	["special", "/signup", function(req, res, next) {
		delete res.body.password;
		next();
	}],
	//Add _owner property to posted object (overwriting it if it was specified)
	["before", "*",
		function(req, res, next) {
			getUser(req);
			if (req.method === "POST" && req.user._id) {
				req.body._owner = req.user._id;
			}
			next();
		}
	],
	//Handle login
	["special", "/login", auth.userManagement.login],
];

module.exports = e;

e.authenticate = function(req, res, next) {
	auth.acl(req, res, next);
};

e.signup = function(req, res, next) {
	auth.signup(req, res, next);
}

e.login = function(req, res, next) {
	auth.login(req, res, next);
}