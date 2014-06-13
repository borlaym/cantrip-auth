var auth = {
	/**
	 * This middleware makes sure that the user making a request is authorized to do so.
	 * Restrictions to paths are stored in the _acl meta object.
	 * By default every user can do anything.
	 */
	acl: function(req, res, next) {
		//Check if there is an Authorization header or the token is passed in as the GET parameter accessToken
		if (req.get("Authorization") || req.query.accessToken) {
			var token = req.get("Authorization") ? req.get("Authorization").split(" ")[1] : req.query.accessToken;
			try {
				var user = auth.decrypt(token);
			} catch (err) {
				var user = undefined;
			}
			if (user && user.expires > (new Date()).getTime()) {
				req.user = _.find(Cantrip.data._users, function(u) {
					return u._id === user._id
				});
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
		var acl = req.data._acl;
		var url = req.path;
		//strip "/" character from the end of the url
		if (url[url.length - 1] === "/") url = url.substr(0, url.length - 1);

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
							var target = _.last(req.nodes);
							if (target._owner === req.user._id) {
								next();
								return;
							}
						}
					}
				}
			}
		}

		//Check if we found any restrictions along the way
		if (foundRestriction) {
			res.status(403).send({
				"error": "Access denied."
			});
		} else {
			next();
		}
	},

	userManagement: {
		signup: function(req, res, next) {
			//Redirect to write to the _users node instead
			req.nodes = [req.data._users];
			//Check for required password field
			if (!req.body.password) {
				res.status(400).send({
					"error": "Missing required field: password."
				});
				return;
			}
			//Create password hash
			req.body.password = md5(req.body.password + "" + req.data._salt);
			//If it's not an array or doesn't exist, create an empty roles array
			req.body.roles = [];
			next();
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

			res.send({
				token: auth.encrypt(toCrypt),
				expires: expires
			});
		}
	},

	encrypt: function(obj) {
		var cipher = crypto.createCipher('aes-256-cbc', this.data._salt);
		var crypted = cipher.update(JSON.stringify(obj), 'utf8', 'hex')
		crypted += cipher.final('hex');
		return crypted;
	},

	decrypt: function(string) {
		var decipher = crypto.createDecipher('aes-256-cbc', this.data._salt);
		var dec = decipher.update(string, 'hex', 'utf8')
		dec += decipher.final('utf8');
		return JSON.parse(dec);
	}
}

var e = auth.acl;
e.registerMiddleware = [
	["before", "/_auth/signup", function(error, req, res, next) {
		next();
	}],
	["before", "/_auth/signup", auth.userManagement.signup],
	["alter", "/_auth/signup", function(error, req, res, next) {
		delete res.body.password;
	}],
	["before", "/_auth/login", function(error, req, res, next) {
		next();
	}],
	["before", "/_auth/login", auth.userManagement.login],
]

module.exports = e;