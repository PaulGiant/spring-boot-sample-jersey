/**
 * 
 */
package sample.jersey;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Priority;
import javax.management.relation.Role;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 *
 * @author <a href="mailto:stefano.zuccaro@postecom.it">Stefano Zuccaro</a> Apr 12, 2016
 *
 */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class JWTAuthFilter implements ContainerRequestFilter {
	
	private final static Logger LOG = LoggerFactory.getLogger(JWTAuthFilter.class); 

	{
		LOG.info("JWTAuthFilter STARTUP {}",this);
	}

	@Context
	private UriInfo uriInfo;
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		final String smuser = requestContext.getHeaderString("sm_user");
		LOG.info("JWTAuthFilter smuser={}", smuser);
		
		if (smuser != null) {
			final SecurityContext securityContext = requestContext.getSecurityContext();
			final List<Role> roles = findUserRoles(smuser);

			requestContext.setSecurityContext(new SecurityContext() {
				@Override
				public Principal getUserPrincipal() {
					return new Principal() {
						@Override
						public String getName() {
							return smuser;
						}
					};
				}

				@Override
				public boolean isUserInRole(String role) {
					return roles.contains(role);
				}

				@Override
				public boolean isSecure() {
					return uriInfo.getAbsolutePath().toString().startsWith("https");
				}

				@Override
				public String getAuthenticationScheme() {
					return "Token-Based-Auth-Scheme";
				}
			});
		} else {
			LOG.error("JWTAuthFilter HTTP 401: smuser is null");
			// requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
		}
	}
	
	public List<Role> findUserRoles(String userid){
		// retrieve user roles
		return new ArrayList<Role>();
	}

	public static class InvalidJwtException extends Exception {

	}
}