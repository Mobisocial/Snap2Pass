package edu.stanford.junction.snap2pass;

import org.json.JSONObject;

import edu.stanford.junction.android.IntentLauncher;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.os.Bundle;
import android.util.Log;

public class AccountSetter extends Activity {
	private static String SCAN_APP = "com.google.zxing.client.android";
	private static String SCAN_ACTION = "com.google.zxing.client.android.SCAN";
	private static String SCAN_LINK = "market://search?q=pname%3Acom.google.zxing.client.android";
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		
		Intent intent = new Intent(SCAN_ACTION);
        intent.putExtra("SCAN_MODE", "QR_CODE_MODE");
		IntentLauncher.launch(AccountSetter.this, 
				  intent,
				  SCAN_APP,
				  SCAN_LINK,
				  "Barcode Scanner");
	}
	
	
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
			if (intent != null && SCAN_ACTION.equals(intent.getAction())) {
				if (resultCode == Activity.RESULT_OK) {
					try {
				        String contents = intent.getStringExtra("SCAN_RESULT");
				        JSONObject obj = new JSONObject(contents);
				        
				        String username = obj.getString("username");
				        String key = obj.getString("key");
				        
				        SharedPreferences prefs = getSharedPreferences("main", 0);
				        Editor ed = prefs.edit();
				        ed.putString("username", username);
				        ed.putString("key", key);
				        ed.commit();
				        
				        finish();
					} catch (Exception e) {
						Log.e("snap2pass","Could not set account",e);
					}
				}
			}
	}
}
