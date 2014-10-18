package hu.sjuhasz.lib.appengine;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;

public class OAuthContext {

	private static final ThreadLocal<OAuthContext> context = new ThreadLocal<OAuthContext>();
	 
    public static void createContext(HttpTransport transport, JsonFactory jsonFactory, String userId, Credential credential) {
    	context.set(new OAuthContext(transport, jsonFactory, userId, credential));
    }
 
    public static OAuthContext getContext() {
        return context.get();
    }
 
    public static void cleanup() {
        context.remove();
    }
	    
	private final String userId;
	private final Credential credential;
	private final HttpTransport transport;
	private final JsonFactory jsonFactory;
	
	public OAuthContext(
			final HttpTransport transport, 
			final JsonFactory jsonFactory,
			final String userId,
			final Credential credential) {
		this.transport = transport;
		this.jsonFactory = jsonFactory;
		this.userId = userId;
		this.credential = credential;
	}
	public String getUserId() {
		return userId;
	}
	
	public Credential getCredential() {
		return credential;
	}

	public HttpTransport getTransport() {
		return transport;
	}

	public JsonFactory getJsonFactory() {
		return jsonFactory;
	}
	
}
