var JunctionMaker = function()
{
	var _hostURL;

	function getXMPPConnection(onConnect) {
		var _jid='junction';
		var _pw='junction';

		var connection = new Strophe.Connection('http://' + _hostURL + '/http-bind');
		connection.connect(_jid,_pw,onConnect);
		return connection;
	}

	function Junction(activity,actor) {
		var _sessionID;
		var _isActivityCreator = false;

		var _activityDesc = activity;
		if (activity&&activity.sessionID) {
			_sessionID = activity.sessionID;
		} else {
			var query = parseUri(window.location).query;
			if ((i = query.indexOf('jxsessionid=')) >= 0) {
				_sessionID = query.substring(i+12);
				if ((i=_sessionID.indexOf('&')) >= 0) {
					_sessionID = _sessionID.substring(0,i);
				}

				if ((i = query.indexOf('jxswitchboard=')) >= 0) {
					_hostURL = query.substring(i+14);
					if ((i=_hostURL.indexOf('&')) >= 0) {
						_hostURL = _hostURL.substring(0,i);
					}
				}
			}  else {
				_sessionID = randomUUID(); 
				_isActivityCreator = true;
			}
		}
		if (activity&&activity.host) {
			_hostURL = activity.host;
		} else {

		}
		var _actorID = randomUUID();

		var MUC_ROOM = _sessionID;
		var MUC_COMPONENT = 'conference.'+_hostURL;
		

		function onPresence(msg){
			var user = Strophe.getResourceFromJid(msg.getAttribute('from'));
			var type = msg.getAttribute('type');

			// TODO: build up roster for room.
			if (type == null && user == _actorID) {
				var roomdesc=JSON.stringify(_activityDesc);
				//alert(roomdesc);
				// if I'm owner, unlock room
				var form = $iq({to: MUC_ROOM + "@" + MUC_COMPONENT,
						type: 'set'})
					  .c("query", {xmlns: "http://jabber.org/protocol/muc#owner"})
					  .c("x", {xmlns: "jabber:x:data", type:"submit"})
					  .c("field", {"var": "muc#roomconfig_roomdesc"})
					  .c("value").t(roomdesc)
 					  .up().up()
					  .c("field", {"var": "muc#roomconfig_whois"})
					  .c("value").t("moderators")
					  .up().up()
					  .c("field", {"var": "muc#roomconfig_publicroom"})
					  .c("value").t("0")
					  .tree();

				_xmppConnection.send(form);

				if (actor) {
					actor.actorID = _actorID;
					if (_isActivityCreator && actor.onActivityCreate) {
						actor.onActivityCreate();
					}
					if (actor.onActivityJoin) {
						actor.onActivityJoin();
					}
				}
				return false;
			}
			return true;
		}


		function onConnect(status){
			if (status == Strophe.Status.CONNECTED) {
				var old = window.onbeforeunload;
				var discon = 
					function() {
						_xmppConnection.disconnect();
					};
				if (typeof window.onbeforeunload != 'function') {
					window.onbeforeunload = discon;
				} else {
					window.onbeforeunload = function() {
						old();
						discon();
					}
				}

				_xmppConnection.send(
					$pres({to: MUC_ROOM + "@" + MUC_COMPONENT + "/" + _actorID})
					  .c("x", {xmlns: "http://jabber.org/protocol/muc"}).tree());


				_xmppConnection.addHandler(onPresence, 
							null, 
							'presence',
							null,null,null); 

				if (actor && actor.onMessageReceived) {
					var f = function(msg) {

						var from = msg.getAttribute('from');
						var i = from.lastIndexOf('/');
						if (i >= 0) {
							from = from.substring(i+1);
						}
						var type = msg.getAttribute('type');
						var body = msg.getElementsByTagName("body")[0].childNodes[0];
						//var user = Strophe.getResourceFromJid(from);

						var jxheader = new Object();
						jxheader.from = from;

						if ((type == "groupchat" || type == "chat") && body) {
							try {
								var content = JSON.parse(body.nodeValue);
								if (content.jx && content.jx.targetRole) {
									if (!actor.roles) {
										return true;
									}
									for (i=0;i<actor.roles.length;i++) {
										if (actor.roles[i] == content.jx.targetRole) {
											actor.onMessageReceived(content,jxheader);
											return true;
										}
									}
									return true;
								}
								actor.onMessageReceived(content,jxheader);
							} catch (e) {
								return true;
							}
						}
						return true;
					};
					_xmppConnection.addHandler(f, 
							null, 
							'message',
							null,null,null); 
				}
			}
		}


		var _xmppConnection = getXMPPConnection(onConnect);

		return  {
			  activityDesc : _activityDesc,
			  getSessionID : function() { return _sessionID },

			  sendMessageToActor: function (actorID, msg) {
				if (!(typeof msg == 'object')) {
					msg = {v:msg};
				}
				msg = JSON.stringify(msg);
				_xmppConnection.send($msg({to: MUC_ROOM + "@" + MUC_COMPONENT + '/' + actorID, 
					type: "chat", id: _xmppConnection.getUniqueId
				}).c("body")
				  .t(msg).up()
				  .c("nick", {xmlns: "http://jabber.org/protocol/nick"})
				  .t(_actorID).tree())
			  },
			  sendMessageToRole: function (role, msg) {
				if (!(typeof msg == 'object')) {
					msg = {v:msg};
				}
				if (msg.jx) {
					msg.jx.targetRole = role;
				} else {
					msg.jx = { targetRole: role };
				}
				msg = JSON.stringify(msg);
				_xmppConnection.send($msg({to: MUC_ROOM + "@" + MUC_COMPONENT, 
					type: "groupchat", id: _xmppConnection.getUniqueId
				}).c("body")
				  .t(msg).up()
				  .c("nick", {xmlns: "http://jabber.org/protocol/nick"})
				  .t(_actorID).tree())
			  
			  },
			  sendMessageToSession: function (msg) {
				if (!(typeof msg == 'object')) {
					msg = {v:msg};
				}
				msg = JSON.stringify(msg);
				_xmppConnection.send($msg({to: MUC_ROOM + "@" + MUC_COMPONENT, 
					type: "groupchat", id: _xmppConnection.getUniqueId
				}).c("body")
				  .t(msg).up()
				  .c("nick", {xmlns: "http://jabber.org/protocol/nick"})
				  .t(_actorID).tree())
			  },

			  getInvitationURI : function () {
				var url = '';
				if (arguments.length == 0) {
					url = 'junction://' + _hostURL + "/" + _sessionID;
				} else if (arguments[0] != false) {
					url = 'junction://' + _hostURL + "/" + _sessionID + "?requestedRole="+arguments[0];
				}
				return url;
			  },
			  getInvitationForWeb : function(role) { // TODO: add role parameter
								 // TODO: AcSpec should be { roles: { "player": { ... } } }
				var url='';
				if (role && _activityDesc.roles) {
					for (i=0;i<_activityDesc.roles.length;i++) {
						if (_activityDesc.roles[i].role==role) {
							var plat=_activityDesc.roles[i].platforms;
							for (j=0;j<plat.length;j++) {
								if (plat[j].platform=='web') {
									url=plat[j].url.toString();
									break;
								}
							}
							break;
						}
					}
					if (url=='') url=document.location.toString(); // return false?
				} else {
					url=document.location.toString();
				}
				var params = 'jxsessionid='+_sessionID+'&jxswitchboard='+_hostURL;
				if (url.indexOf('?')>0) {
					return url + '&' + params;
				} else {
					return url + '?' + params;
				}
			  },
			  getInvitationQR : function () {
				var url;
				var size;
    				//var content = new Object();
				//content.sessionID = _sessionID;
				//content.host = _hostURL;
				//content.ad = _activityDesc;

				if (arguments.length == 0) {
					url = 'junction://' + _hostURL + "/" + _sessionID;
				} else if (arguments[0] != false) {
					url = 'junction://' + _hostURL + "/" + _sessionID + "?requestedRole="+arguments[0];
					//content.requestedRole = arguments[0];
				}
				if (arguments.length == 2) {
					size = arguments[1]+'x'+arguments[1];
				} else {
					size = '250x250';
				}

				//return 'http://chart.apis.google.com/chart?cht=qr&chs='+size+'&chl='+encodeURIComponent('{jxref:"'+url+'"}');
				//return 'http://chart.apis.google.com/chart?cht=qr&chs='+size+'&chl='+encodeURIComponent(JSON.stringify(content));
				return 'http://chart.apis.google.com/chart?cht=qr&chs='+size+'&chl='+encodeURIComponent(url);
				
			  },

			  getActorsForRole : function() { },
			  getRoles : function() { },
			  disconnect : function() { _xmppConnection.disconnect(); },
			};

	}

	return {
		create: function()
		{
			if (arguments.length == 1) {
				_hostURL = arguments[0];
			} else {
				_hostURL = false;
			}

			return {
				newJunction: function()
				{
					if (typeof(arguments[0])=='string' && arguments[0].indexOf('://') > 0) {
						parsed = parseUri(arguments[0]);
						// hack for legacy:
						var activity = { host: parsed.host };
						activity.sessionID = parsed.path.substring(1);
						arguments[0] = activity;
					}
					if (!arguments[0].host && !_hostURL) {
						return false;
					}
					if (arguments.length == 1) {
						return Junction(arguments[0],false);
					} else if (arguments.length == 2) {
						var jx = Junction(arguments[0],arguments[1]);
						if (arguments[1]){
							arguments[1].junction = jx;
							arguments[1].leave = function() { jx.disconnect(); };
						}
						return jx;
					} else {
						return false;
					}
				}

				// must use a callback since javascript is asynchronous
				, activityDescriptionCallback: function(uri, cb) {
					var parsed = parseUri(uri);
					var switchboard = parsed.host;
					var sessionID = parsed.path.substring(1);

					var _room = sessionID;
					var _component = 'conference.'+switchboard;

					var _jid='junction';
					var _pw='junction';
					var connection = new Strophe.Connection('http://' + switchboard + '/http-bind');
					//connection.rawOutput = function(data) { $('#raw').append('<br/><br/>OUT: '+data.replace(/</g,'&lt;').replace(/>/g,'&gt;')); }
					//connection.rawInput = function(data) { $('#raw').append('<br/><br/>IN: '+data.replace(/</g,'&lt;').replace(/>/g,'&gt;')); }

					var getInfo = function(a) {
						var fields = a.getElementsByTagName('field');
						for (i=0;i<fields.length;i++) {
							if (fields[i].getAttribute('var') == 'muc#roominfo_description') {
								var desc = fields[i].childNodes[0].childNodes[0].nodeValue; // get text of value
								var json = JSON.parse(desc);
								cb(json);
								connection.disconnect();
								return false;
							}
						}
						
						return true;
					};

					connection.connect(_jid,_pw, function(status){
						if (status == Strophe.Status.CONNECTED) {
							// get room info for sessionID

							connection.send(
							$iq({to: _room + "@" + _component, type: 'get'})
							  .c("query", {xmlns: "http://jabber.org/protocol/disco#info"}).tree());


							connection.addHandler(getInfo, 
								'http://jabber.org/protocol/disco#info', 
								null,
								null,null,null); 

					

						}
					});
				}

				, inviteActorService: function(uri) {
					this.activityDescriptionCallback(uri, function(ad) {
						var role = '';
						if ((d = uri.indexOf('requestedRole=')) >= 0) {
							role = uri.substring(d+14);
							if ((d=role.indexOf('&'))>=0) {
								role = role.substring(0,d);
							}
						}
						if (role == '' || !ad.roles) return;
						for (i=0;i<ad.roles.length;i++) {
							if (ad.roles[i].role==role) {
								platforms = ad.roles[i].platforms;
								for (j=0;j<platforms.length;j++){
									if (platforms[j].platform=='jxservice') {
										actor = {
												serviceName: platforms[j].serviceName,
												onActivityJoin:
													function() {
														invite = {
															activity: uri,
															serviceName: this.serviceName
														};
														this.junction.sendMessageToSession(invite);
													}
											}

									var remoteURI = 'junction://';
									if (platforms[j].switchboard) remoteURI += platforms[j].switchboard;
									else remoteURI += parseUri(uri).host;
									remoteURI += '/jxservice';

										JunctionMaker.create().newJunction(remoteURI, actor);
									}
								}
							}
						}
					});
				}
			};
		}
	}
}();


// TODO: Use JQuery to load this script from another file

/* randomUUID.js - Version 1.0
 * 
 * Copyright 2008, Robert Kieffer
 * 
 * This software is made available under the terms of the Open Software License
 * v3.0 (available here: http://www.opensource.org/licenses/osl-3.0.php )
 *
 * The latest version of this file can be found at:
 * http://www.broofa.com/Tools/randomUUID.js
 *
 * For more information, or to comment on this, please go to:
 * http://www.broofa.com/blog/?p=151
 */

/**
 * Create and return a "version 4" RFC-4122 UUID string.
 */

function randomUUID() {
  var s = [], itoh = '0123456789ABCDEF';
  // Make array of random hex digits. The UUID only has 32 digits in it, but we
  // allocate an extra items to make room for the '-'s we'll be inserting.
  for (var i = 0; i <36; i++) s[i] = Math.floor(Math.random()*0x10);

  // Conform to RFC-4122, section 4.4
  s[14] = 4;  // Set 4 high bits of time_high field to version
  s[19] = (s[19] & 0x3) | 0x8;  // Specify 2 high bits of clock sequence

  // Convert to hex chars
  for (var i = 0; i <36; i++) s[i] = itoh[s[i]];

  // Insert '-'s
  s[8] = s[13] = s[18] = s[23] = '-';

  return s.join('');
}



// parseUri 1.2.2
// (c) Steven Levithan <stevenlevithan.com>
// MIT License

function parseUri (str) {
	var	o   = parseUri.options,
		m   = o.parser[o.strictMode ? "strict" : "loose"].exec(str),
		uri = {},
		i   = 14;

	while (i--) uri[o.key[i]] = m[i] || "";

	uri[o.q.name] = {};
	uri[o.key[12]].replace(o.q.parser, function ($0, $1, $2) {
		if ($1) uri[o.q.name][$1] = $2;
	});

	return uri;
};

parseUri.options = {
	strictMode: false,
	key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
	q:   {
		name:   "queryKey",
		parser: /(?:^|&)([^&=]*)=?([^&]*)/g
	},
	parser: {
		strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
		loose:  /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
	}
};

