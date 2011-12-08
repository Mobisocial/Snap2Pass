package edu.stanford.junction.snap2pass;

import java.net.URI;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

import edu.stanford.junction.JunctionMaker;
import edu.stanford.junction.android.AndroidJunctionMaker;
import edu.stanford.junction.android.AndroidJunctionMaker.Intents;
import edu.stanford.junction.api.activity.JunctionActor;
import edu.stanford.junction.api.messaging.MessageHeader;
import edu.stanford.junction.provider.xmpp.XMPPSwitchboardConfig;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;

public class LoginAgent extends Activity {
	ProgressDialog mProgress = null;
	LoginTask mLoginTask = null;
	
	@Override
	public void onConfigurationChanged(Configuration newConfig) {
		super.onConfigurationChanged(newConfig);
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		mLoginTask = new LoginTask(); 
		if (mProgress == null) {
			mProgress = new ProgressDialog(LoginAgent.this);
			mProgress.setTitle("Logging you in");
			mProgress.setIndeterminate(true);
			mProgress.setOnCancelListener(new DialogInterface.OnCancelListener() {
				
				public void onCancel(DialogInterface dialog) {
					mLoginTask.cancel(true);
				}
			});
		}
		
		if (AndroidJunctionMaker.isJoinable(LoginAgent.this)) {
			mLoginTask.execute((Void)null);
		} else {
			Log.d("snap2pass","Could not join intent in LoginAgent");
			finish();
		}
	}


	class LoginTask extends AsyncTask<Void, String, Void> {
		private LoginActor mLoginActor=null;
		private String authResponse = null;
		
		@Override
		protected void onPreExecute() {
			mProgress.show();
		}
		
		@Override
		protected void onCancelled() {
			Log.d("snap2pass","Cancelling login.");
			mLoginActor.cancelLogin();
		}

		@Override
		protected Void doInBackground(Void... params) {
			publishProgress("Computing response ...");
			
			Bundle bundle = LoginAgent.this.getIntent().getExtras();
			try {
				URI uri = new URI(bundle.getString(Intents.EXTRA_ACTIVITY_SESSION_URI));
				String sid = JunctionMaker.getSessionIDFromURI(uri);
				
				mLoginActor = new LoginActor(sid);
				authResponse = mLoginActor.getResponse();
				publishProgress("Connecting ...");
			} catch (Exception e) {
				Log.e("snap2pass","invalid session URI",e);
				return null;
			}
			
			XMPPSwitchboardConfig config = new XMPPSwitchboardConfig("prpl.stanford.edu");
			AndroidJunctionMaker jm = AndroidJunctionMaker.getInstance(config);
			jm.newJunction(LoginAgent.this, mLoginActor);
			
			// A little silly that most of the work in the
			// AsyncTask is in another thread, but so it goes.
			synchronized(mLoginActor) {
				try {
					mLoginActor.wait();
				} catch (InterruptedException e) {
					Log.e("snap2pass","Interrupt exception while logging in",e);
				}
			}

			return null;
		}

		@Override
		protected void onProgressUpdate(String... progress) {
			mProgress.setMessage(progress[0]);
			/*if (authResponse == null) {
				mProgress.setMessage(progress[0]);
			} else {
				String msg = progress[0] + "\n\n Your auth code is " + authResponse;
				mProgress.setMessage(msg);
			}*/
		}

		@Override
		protected void onPostExecute(Void result) {
			mProgress.dismiss();
			finish();
		}
		
		public void setProgress(String progress){
			super.publishProgress(progress);
		}
	};

	/**
	 * A JunctionActor for logging in to a Snap2Pass
	 * session. A LoginActor can only be used with
	 * one challenge, passed in to its constructor.
	 * 
	 */
	private class LoginActor extends JunctionActor {
		private String mChallenge = null;
		private String mResponse = null;
		private String mUsername = null;
		private String mKey = null;
		
		public LoginActor(String challenge) {
			super("mobile");
			
			mChallenge=challenge;
			
			SharedPreferences prefs = getSharedPreferences("main", 0);
			mUsername = prefs.getString("username", null);
			mKey = prefs.getString("key", null);

		}
		
		public void cancelLogin() {
			leave();
		}
		
		@Override
		public void onMessageReceived(MessageHeader header, JSONObject message) {
			if (getActorID().equals(header.getSender())) {
				// only send one auth message.
				this.leave();
				
				// Finishes the AsyncTask
				synchronized(LoginActor.this) {
					LoginActor.this.notify();
				}
			}
		}

		@Override
		public void onActivityJoin() {
			try {
				mLoginTask.setProgress("Logging in ...");

				String response = getResponse();

				JSONObject msg = new JSONObject();
				msg.put("action","authenticate");
				msg.put("username",mUsername);
				msg.put("authkey",response);

				this.sendMessageToSession(msg);
			} catch (Exception e) {
				Log.e("snap2pass","Failed to log in",e);
			}
		};
		
		public String getResponse() {
			if (mResponse != null) return mResponse;
			
			mResponse = computeBase64_HMAC(mChallenge, mKey);
			return mResponse;
		}
	};
	
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static String computeBase64_HMAC(String data, String key) {
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			mac.init(signingKey);

			// compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(data.getBytes());

			// base64-encode the hmac
			String ans = new String(Base64Coder.encode(rawHmac));
			return ans;
		} catch (Exception e) {
			Log.d("snap2pass","Error computing HMAC",e);
			return null;
		}
	}
}
