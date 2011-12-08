$(function() {
  var activity = {
		  ad: 'edu.stanford.prpl.authjunction'
		 ,roles: [ { role: 'user', 
                               platforms: [{platform:'android',
                                            package:'edu.stanford.prpl.authjunction',
	                                    url:'http://prpl.stanford.edu/android/AuthJunction-0.1-SNAPSHOT.apk'}] },
			   { role: 'browser', platforms: [{platform:'web'}] }
		         ]
		};

  var actor = {
	          roles: ['browser']
		, onActivityJoin: 
		  function() {
			this.junction.sendMessageToRole("user",{status:"READY"});
		 }

		, onMessageReceived: function(msg) {
			if (msg.username) {
			  document.getElementById('gaia_loginform').Email.value=
	    			msg.username;
		  	  document.getElementById('gaia_loginform').Passwd.value=
		    		msg.password;
	  		  document.getElementById('gaia_loginform').submit();
			} else {
				this.junction.sendMessageToRole("user",{status:"READY"});
			}
		 }



		};


  var jm = JunctionMaker.create('prpl.stanford.edu');
  var jx = jm.newJunction(activity,actor);

  var img = jx.getInvitationQR('user');
  $('#qrframe').append('<img src="'+img+'"/>');

});
