package edu.stanford.junction.snap2pass;

import edu.stanford.junction.android.AndroidJunctionMaker;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

public class Snap2Pass extends Activity {
	
	private class MenuItems {
		static final int GET_CREDS = 1;
	}
	
	@Override
	public void onConfigurationChanged(Configuration newConfig) {
		super.onConfigurationChanged(newConfig);
	}
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        ((Button)findViewById(R.id.btnLogin)).setOnClickListener(mLoginClickListener);
    }
    
    
    private View.OnClickListener mLoginClickListener
    	= new View.OnClickListener() {
			
			public void onClick(View v) {
				// Make sure they have an account
				if (!isAccountSet()){
					AlertDialog alert =
						new AlertDialog.Builder(Snap2Pass.this)
							.setMessage("You must set an account before logging in. Use the menu button to do so.")
							.setTitle("Please specify an account.")
							.setPositiveButton("Okay", new DialogInterface.OnClickListener() {
								public void onClick(DialogInterface arg0, int arg1) {
									
								}
							})
							.create();
					alert.show();
					
					return;
				}
				AndroidJunctionMaker.findActivityByScan(Snap2Pass.this);
			}
		};

		
	public boolean onCreateOptionsMenu(android.view.Menu menu) {
		menu.add(0, MenuItems.GET_CREDS, 0, "Get Account");
		return true;
	};
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case MenuItems.GET_CREDS:
			Intent getAccount = new Intent(Snap2Pass.this,AccountSetter.class);
			startActivity(getAccount);
			break;
		}
		return super.onOptionsItemSelected(item);
	}
	
	private boolean isAccountSet() {
		SharedPreferences prefs = getSharedPreferences("main", 0);
		String username = prefs.getString("username", null);
		String key = prefs.getString("key", null);
		
		return (key != null && username != null);
	}
}