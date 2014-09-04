var md5 = require('MD5');
var _ = require('lodash');
var crypto = require('crypto');
var nodemailer = require('nodemailer');

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
		console.log(req.cantrip);
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
							var target = req.targetNode;
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
			//Redirect to write to the _users node instead
			req.targetNode = req.data._users;
			Object.defineProperty(req, 'path', {
				get: function() {
					return "/_users";
				}
			});

			//Check for required password field
			if (!req.body.password) {
				res.status(400).send({
					"error": "Missing required field: password."
				});
				return;
			}

			//If email verification is turned on, the email field is required too
			if (e.options.emailVerification && !req.body[e.options.emailField]) {
				res.status(400).send({
					"error": "Missing required field: " + e.options.emailField + "."
				});
				return;
			}

			//Create password hash
			req.body.password = md5(req.body.password + "" + req.data._salt);

			//If it's not an array or doesn't exist, create an empty roles array
			req.body.roles = [];

			//If email verification is turned on, add a verification token
			req.body.verified = true;
			if (e.options.emailVerification) {
				req.body.token = md5(Math.floor(Math.random() * 100000000) + JSON.stringify(req.body));
				req.body.verified = false;
			}

			//Procceed to posting to _users
			next();
		},
		login: function(req, res, next) {
			var user = _.find(req.data._users, function(u) {
				return u._id === req.body._id
			});

			//Check password
			if (!user || user.password !== md5(req.body.password + "" + req.data._salt)) {
				res.status(403).send({
					"error": "Wrong _id or password."
				});
				return;
			}

			//If email verification is turned on, check if the user was verified
			if (e.options.emailVerification && !user.verified) {
				res.status(403).send({
					"error": "User is not verified."
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
				token: auth.encrypt(toCrypt, req.data._salt),
				expires: expires
			});
		},
		/**
		 * Verify your email after registration. Gets the user belonging to the sent token if there is one and verifies that user
		 */
		verify: function(req, res, next) {
			if (!req.body.token) {
				res.status(403).send({
					"error": "Missing verification token."
				});
				return;
			}

			req.dataStore.get("/_users", function(err, users) {
				var user = _.find(users, function(u) {
					return u.token === req.body.token;
				});
				if (user) {
					req.dataStore.set("/_users/" + user._id + "/verified", true, function(err, r) {
						if (err) {
							res.status(300).send({
								"error": "Internal error."
							});
						} else {
							req.cantrip.syncData(req, res, next);
							res.status(200).send({
								"success": true
							});
						}
					});
				} else {
					res.status(400).send({
						"error": "Wrong token."
					});
					return;
				}
			});
		},

		/**
		 * Handle password reset. POST means a reset request, which sends out a reset token. PUT means the actual reset.
		 * Requesting a reset requires an email.
		 * Resetting the password requires an oldPassword, a newPassword and a token.
		 */
		reset: function(req, res, next) {
			//Reset Request
			if (req.method === "POST") {
				if (!req.body[e.options.emailField]) {
					res.status(400).send({
						"error": "Missing required parameter " + e.options.emailField
					});
					return;
				}
				req.dataStore.get("/_users", function(err, users) {
					var user = _.find(users, function(u) {
						return u[e.options.emailField] === req.body[e.options.emailField];
					});
					if (!user) {
						res.status(404).send({
							"error": "User not found"
						});
						return;
					}
					var token = md5(Math.floor(Math.random() * 10000000) + JSON.stringify(user));
					req.dataStore.set("/_users/" + user._id + "/token", token, function(err, r) {
						if (err) {
							console.log(err);
						}
						var mail = nodemailer.createTransport(e.options.emailServer);
						mail.sendMail({
							from: 'Fred Foo <foo@blurdybloop.com>', // sender address
							to: user[e.options.emailField], // list of receivers
							subject: 'Password reset request', // Subject line
							html: '<b>Your password reset token is: </b>' + token // html body
						}, function(err, info) {
							if (err) {
								console.log(err);
							}
							req.cantrip.syncData(req, res, next);
							res.status(200).send({
								"success": true
							});
						});

					});

				});
			} else {
				//Handling reset
				if (!req.body.token) {
					res.status(400).send({
						"error": "Missing required parameter token."
					});
					return;
				}
				if (!req.body.oldPassword) {
					res.status(400).send({
						"error": "Missing required parameter oldPassword."
					});
					return;
				}
				if (!req.body.newPassword) {
					res.status(400).send({
						"error": "Missing required parameter newPassword."
					});
					return;
				}
				req.dataStore.get("/_users", function(err, users) {
					var user = _.find(users, function(u) {
						return u.token === req.body.token;
					});
					if (!user) {
						res.status(404).send({
							"error": "Reset request not found."
						});
						return;
					}
					req.dataStore.get("/_salt", function(err, salt) {
						if (md5(req.body.oldPassword + salt) !== user.password) {
							res.status(400).send({
								"error": "Wrong password."
							});
							return;
						}

						req.dataStore.set("/_users/" + user._id + "/password", md5(req.body.newPassword + salt), function(err, r) {
							req.cantrip.syncData(req, res, next);
							res.status(200).send({
								"success": true
							});
							return;
						});
					});
				});
			}
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
	//Allows POSTing to non-existend node /auth/signup
	["before", "/auth/signup",
		function(error, req, res, next) {
			if (req.method === "POST") return next();
			else return next(error);
		}
	],
	//Handle signup
	["before", "/auth/signup", auth.userManagement.signup],
	//Remove password hash from response after signing up
	["alter", "/auth/signup",
		function(req, res, next) {
			delete res.body.password;
			delete res.body.token;
			delete res.body.verified;
			next();
		}
	],
	//Send email with verification token to user
	["after", "/auth/signup",
		function(req, res, next) {
			var mail = nodemailer.createTransport(e.options.emailServer);
			mail.sendMail({
				from: 'Fred Foo <foo@blurdybloop.com>', // sender address
				to: req.body[e.options.emailField], // list of receivers
				subject: 'Please verify your email address', // Subject line
				html: '<b>Your verification code is: </b>' + req.body.token // html body
			}, function(err, info) {
				if (err) {
					console.log(err);
				}
				next();
			});
		}
	],
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
	//Allows POSTing to non-existend node /auth/login
	["before", "/auth/login",
		function(error, req, res, next) {
			if (req.method === "POST") return next();
			else return next(error);
		}
	],
	//Handle login
	["before", "/auth/login", auth.userManagement.login],

	//Allow POSTing to non-existent node /auth/verify
	["before", "/auth/verify",
		function(error, req, res, next) {
			if (req.method === "POST") return next();
			else return next(error);
		}
	],
	//Handle verification
	["before", "/auth/verify", auth.userManagement.verify],

	//Allow POSTing and PUTting to non-existent node /auth/reset
	["before", "/auth/reset",
		function(error, req, res, next) {
			if (req.method === "POST" || req.method === "PUT") return next();
			else return next(error);
		}
	],
	//Handle verification
	["before", "/auth/reset", auth.userManagement.reset],
];

//Default options used by the middleware
e.options = {
	/**
	 * An email is sent after registering. Before the user sends a request using a defined token sent in the mail, it has a verified: false tag.
	 * @type {Boolean}
	 */
	emailVerification: true,
	/**
	 * The name of the field containing the user's email address. By default it's the _id, but you can redefine it to any other field (like email)
	 * @type {String}
	 */
	emailField: "_id",
	/**
	 * Settings and authentication of the email server
	 * @type {Object}
	 */
	emailServer: {
		//Fill out
	}
};



module.exports = e;