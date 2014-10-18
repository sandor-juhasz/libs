package hu.sjuhasz.lib.appengine;

import com.google.appengine.api.users.User;
import com.google.appengine.api.users.UserServiceFactory;

/**
 * This abstract subclass of the AbstactOAuthFitler adds Google appengine-based
 * method implementations. This includes calculating the user identifier of the
 * current user.
 * 
 * @author Sanyi
 *
 */
public abstract class AbstractAppEngineOAuthFilter extends AbstractOAuthFilter {

	@Override
	protected String getUserId() {
        User user = UserServiceFactory.getUserService().getCurrentUser();
        if (user != null)
        	return user.getUserId();
        else 
        	return null;
	}
	
}
