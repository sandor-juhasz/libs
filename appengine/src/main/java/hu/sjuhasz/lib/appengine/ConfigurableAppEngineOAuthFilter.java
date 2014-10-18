package hu.sjuhasz.lib.appengine;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.appengine.datastore.AppEngineDataStoreFactory;
import com.google.api.client.extensions.appengine.http.UrlFetchTransport;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

public class ConfigurableAppEngineOAuthFilter extends AbstractAppEngineOAuthFilter {

	private static final String DEFAULT_CALLBACK_PATH = "/authCode";
	private static final String DEFAULT_CLIENT_SECRET_RESOURCE = "/client_secret.json";
	private static final String DEFAULT_SCOPES = "";
	private static final String DEFAULT_REDIRECT_AFTER_CALLBACK = "/";
	
	private static final String INIT_PARAM_CALLBACK_PATH = "callbackPath";
	private static final String INIT_PARAM_CLIENT_SECRET_RESOURCE = "clientSecretResource";
	private static final String INIT_PARAM_SCOPES = "scopes";
	private static final String INIT_REDIRECT_AFTER_CALLBACK = "redirectAfterCallback";

	private static final HttpTransport HTTP_TRANSPORT = new UrlFetchTransport();
	private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	private static final AppEngineDataStoreFactory DATA_STORE_FACTORY = AppEngineDataStoreFactory.getDefaultInstance();
	private static GoogleClientSecrets clientSecrets = null;

	private String callbackPath;
	private String clientSecretResource;
	private Collection<String> scopes;
	private String redirectAfterCallback;
	
	private static AuthorizationCodeFlow flow;
	
	@Override
	public void init(FilterConfig filterConfig) throws javax.servlet.ServletException {
		super.init(filterConfig);
		callbackPath = getInitParam(filterConfig, INIT_PARAM_CALLBACK_PATH, DEFAULT_CALLBACK_PATH);
		clientSecretResource = getInitParam(filterConfig, INIT_PARAM_CLIENT_SECRET_RESOURCE, DEFAULT_CLIENT_SECRET_RESOURCE);
		redirectAfterCallback = getInitParam(filterConfig, INIT_REDIRECT_AFTER_CALLBACK, DEFAULT_REDIRECT_AFTER_CALLBACK);
		scopes = getCommaSeparatedInitParam(filterConfig, INIT_PARAM_SCOPES, DEFAULT_SCOPES);
	}	
	
	private String getInitParam(final FilterConfig filterConfig, final String param, final String defaultValue) {
		String paramValue = filterConfig.getInitParameter(param);
		String returnedValue = paramValue != null ? paramValue : defaultValue; 
		
		System.out.format("[ConfigurableAppEngineOAuthFilter] Configuring parameter %s with value %s\n", param, returnedValue);
		
		return returnedValue; 
	}
	
	private Collection<String> getCommaSeparatedInitParam(final FilterConfig filterConfig, final String param, final String defaultValue) {
		String paramValue = getInitParam(filterConfig, param, defaultValue);
		if (paramValue == null || paramValue.equals("")) {
			return Collections.<String>emptySet();
		}
		String[] paramValues = paramValue.split(",");
		Set<String> paramValueSet = new HashSet<String>();
		paramValueSet.addAll(Arrays.asList(paramValues));
		System.out.println("Scopes: "+paramValueSet);
		return Collections.unmodifiableSet(paramValueSet);
	}

	private GoogleClientSecrets getClientSecrets() throws IOException {
		if (clientSecrets == null) {
			clientSecrets = GoogleClientSecrets.load(
					JSON_FACTORY,
					new InputStreamReader(this.getClass().getResourceAsStream(clientSecretResource)));
		}
		return clientSecrets;
	}	
	
	/**
	 * Checks if the pathInfo of the current request is equal with the 
	 * callaback path from the "callbackPath" initialization parameter.   
	 */
	@Override
	protected boolean isAuthorizationCodeCallbackRequest(HttpServletRequest req) {
		if (req==null)
			throw new NullPointerException("req");
		
		return req.getPathInfo() != null && req.getPathInfo().equals(callbackPath);
	}

	/**
	 * Returns the current request's domain and the callback path attached to 
	 * it. This can be calculated from the request URL and the callback path.
	 */
	@Override
	protected String getAuthorizationCodeCallbackUri(HttpServletRequest req) {
		GenericUrl url = new GenericUrl(req.getRequestURL().toString());
		url.setRawPath(callbackPath);
		String urlString = url.build();
		System.out.println("[ConifugrableAppEngineOAuthFilter] using redirect url: "+urlString);
		return urlString;
	}

	@Override
	public AuthorizationCodeFlow getFlow() throws IOException {
		if (flow == null) {
			flow =  new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT,
					JSON_FACTORY, 
					getClientSecrets(),
					scopes)
					.setDataStoreFactory(DATA_STORE_FACTORY)
					.setAccessType("offline")
					.setApprovalPrompt("force").build();
		}
		return flow;
	}

	@Override
	protected void onSuccessfulAuthorization(HttpServletRequest req,
			HttpServletResponse resp) throws IOException {
		resp.sendRedirect(redirectAfterCallback);
	}

	/**
	 * Adding thread local flow.
	 */
	@Override
	protected void callWithOAuth(
			ServletRequest request,
			ServletResponse response, 
			FilterChain chain,
			final String userId,
			final Credential credential) throws IOException,
			ServletException {
		try {
			OAuthContext.createContext(HTTP_TRANSPORT, JSON_FACTORY, userId, credential);
			chain.doFilter(request, response);
		} finally {
			OAuthContext.cleanup();
		}		
	}
	
}
