package hu.sjuhasz.lib.appengine;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;

/**
 * This is a filter which serves as a gate for OAuth-enabled applications.
 * This filter runs before any servlet and ensures that there is a valid
 * OAuth token pair available for the business logic to consume. If there is
 * no token pair available, it will redirect to the Authorization Endpoint
 * to request an authorization code. This filter will process that code
 * and exchange it for a token pair.
 * <p>
 * This filter is an abstract filter, built using the Google OAuth Java API.
 * This filter contains only the abstract flow of the logic and must be 
 * extended to be utilized in a real-world scenario.
 * 
 * @author Sanyi
 *
 */
public abstract class AbstractOAuthFilter implements Filter {

	/**
	 * The default abstract implementation of this filter cannot be configured
	 * with context parameters. All input must be specified through the 
	 * abstract methods of this class.
	 */
	public void init(FilterConfig filterConfig) throws ServletException {	
	}

	/**
	 * No lifecycle event is needed to be processed here.
	 */
	public void destroy() {
	}

	
	/**
	 * TODO: get auth code path from filter config.
	 * Make the Flow available as ThreadLocal.
	 */
	public void doFilter(
			final ServletRequest request, 
			final ServletResponse response,
			final FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse resp = (HttpServletResponse)response;
		
		System.out.println("[OAuthFilter] processing "+req.getRequestURI());		
		if (isAuthorizationCodeCallbackRequest(req)) {
			System.out.println("[OAuthFilter] authCode path was detected.");
			handleAuthorizationCallbackRequest(req, resp);
		} else {
			String userId = getUserId();
			if (userId != null) {
				System.out.println("[OAuthFilter] User "+userId+" was detected.");
				Credential credential = getFlow().loadCredential(userId);
				if (credential == null || credential.getAccessToken() == null) {
					System.out.println("[OAuthFilter] no credential was found or access token is null. Reauthorizing.");
					sendAuthorizationRequest(req, resp);
				} else {
					System.out.println("[OAuthFilter] existing credential for user was found.");
					System.out.println("[OAuthFilterFilter] calling protected resource. "+req.getRequestURI());
					try {
						callWithOAuth(request, response, chain, userId, credential);						
					} catch (Exception e) {
						if (credential.getAccessToken() == null) {
							System.out.println("[OAuthFilter] null access token was detected after processing protected resource. Reauthorizing...");
							sendAuthorizationRequest(req, resp);
						}
					}
				}
			} else {
				if (req.getRequestURI().startsWith("/_ah/")) {
					System.out.println("[OAuthFilter] Processing admin request.");
					chain.doFilter(request, response);
				} else {
					System.out.println("[OAuthFilter] User is not logged in. Please configure user login first.");
				}
			}
		} 
	}

	private void handleAuthorizationCallbackRequest(HttpServletRequest req,
			HttpServletResponse resp) throws IOException {
		AuthorizationCodeResponseUrl responseUrl = createAuthorizationCodeResponseUrl(req);
	    String code = responseUrl.getCode();
	    if (responseUrl.getError() != null) {
	      resp.getWriter().println(responseUrl.getError());
	    } else if (code == null) {
	      resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
	      resp.getWriter().print("Missing authorization code");
	    } else {
	        TokenResponse tokenResponse = getFlow().newTokenRequest(code).setRedirectUri(getAuthorizationCodeCallbackUri(req)).execute();
	        String userId = getUserId();
	        if (userId == null) {
	        	resp.getWriter().println("Cannot identify user while processing authorization code.");
	        } else {
		        Credential credential = getFlow().createAndStoreCredential(tokenResponse, userId);
		        onSuccessfulAuthorization(req, resp);
	        }
	    }						
	}

	private AuthorizationCodeResponseUrl createAuthorizationCodeResponseUrl(
			HttpServletRequest req) {
	    StringBuffer buf = req.getRequestURL();
	    if (req.getQueryString() != null) {
	      buf.append('?').append(req.getQueryString());
	    }
	    return new AuthorizationCodeResponseUrl(buf.toString());
	}

	private void sendAuthorizationRequest(
			final HttpServletRequest req,
			final HttpServletResponse resp) throws IOException {
	    AuthorizationCodeRequestUrl authorizationUrl = getFlow().newAuthorizationUrl();
	    authorizationUrl.setRedirectUri(getAuthorizationCodeCallbackUri(req));
	    String location = authorizationUrl.build();
	    System.out.println("[OAuthFilter] Redirecting to "+location);
	    resp.sendRedirect(location);									
	}
	
	protected void callWithOAuth(
			final ServletRequest request, 
			final ServletResponse response,
			final FilterChain chain,
			final String userId,
			final Credential credential) throws IOException, ServletException {
		chain.doFilter(request, response);		
	}
	
	protected abstract boolean isAuthorizationCodeCallbackRequest(HttpServletRequest req);
	protected abstract String getAuthorizationCodeCallbackUri(HttpServletRequest req);
	protected abstract AuthorizationCodeFlow getFlow() throws IOException;
	protected abstract void onSuccessfulAuthorization(HttpServletRequest req, HttpServletResponse resp) throws IOException;
	protected abstract String getUserId();
}
