package org.jboss.pki.authenticator;
 
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletResponse;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.util.Base64;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.CharChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.MimeHeaders;
import org.jboss.logging.Logger;
import org.jboss.web.CatalinaLogger;
import org.jboss.web.CatalinaMessages;

public class ExtendedSSLAuthenticator
  extends SSLAuthenticator
{
  protected static final String info = "org.apache.catalina.authenticator.SSLAuthenticator/1.0";
  
  public String getInfo()
  {
    return "org.apache.catalina.authenticator.SSLAuthenticator/1.0";
  }
  
  public boolean authenticateBasic(org.apache.catalina.connector.Request request, HttpServletResponse response, LoginConfig config)
    throws IOException
  {
    CatalinaLogger.AUTH_LOGGER.warn("in authenticateBasic");
    Principal principal = request.getUserPrincipal();
    
    String ssoId = (String)request.getNote("org.apache.catalina.request.SSOID");
    if (principal != null)
    {
      if (CatalinaLogger.AUTH_LOGGER.isDebugEnabled()) {
        CatalinaLogger.AUTH_LOGGER.debug("Already authenticated '" + principal.getName() + "'");
      }
      if (ssoId != null) {
        associate(ssoId, request.getSessionInternal(true));
      }
      return true;
    }
    if (ssoId != null)
    {
      if (CatalinaLogger.AUTH_LOGGER.isDebugEnabled()) {
        CatalinaLogger.AUTH_LOGGER.debug("SSO Id " + ssoId + " set; attempting " + "reauthentication");
      }
      if (reauthenticateFromSSO(ssoId, request)) {
        return true;
      }
    }
    String username = null;
    String password = null;
    
    MessageBytes authorization = request.getCoyoteRequest().getMimeHeaders().getValue("authorization");
    
    CatalinaLogger.AUTH_LOGGER.warn("getting authorization header");
    if (authorization != null)
    {
      CatalinaLogger.AUTH_LOGGER.warn(" authorization header is NOT null");
      
      authorization.toBytes();
      ByteChunk authorizationBC = authorization.getByteChunk();
      if (authorizationBC.startsWithIgnoreCase("basic ", 0))
      {
        authorizationBC.setOffset(authorizationBC.getOffset() + 6);
        
        CharChunk authorizationCC = authorization.getCharChunk();
        Base64.decode(authorizationBC, authorizationCC);
        
        int colon = authorizationCC.indexOf(':');
        if (colon < 0)
        {
          username = authorizationCC.toString();
        }
        else
        {
          char[] buf = authorizationCC.getBuffer();
          username = new String(buf, 0, colon);
          password = new String(buf, colon + 1, authorizationCC.getEnd() - colon - 1);
        }
        authorizationBC.setOffset(authorizationBC.getOffset() - 6);
      }
      principal = this.context.getRealm().authenticate(username, password);
      if (principal != null)
      {
        register(request, response, principal, "BASIC", username, password);
        

        return true;
      }
    }
    MessageBytes authenticate = request.getResponse().getCoyoteResponse().getMimeHeaders().addValue(BasicAuthenticator.AUTHENTICATE_BYTES, 0, BasicAuthenticator.AUTHENTICATE_BYTES.length);
    





    CharChunk authenticateCC = authenticate.getCharChunk();
    authenticateCC.append("Basic realm=\"");
    if (config.getRealmName() == null) {
      authenticateCC.append("Realm");
    } else {
      authenticateCC.append(config.getRealmName());
    }
    authenticateCC.append('"');
    authenticate.toChars();
    response.sendError(401);
    
    return false;
  }
  
  public boolean authenticate(org.apache.catalina.connector.Request request, HttpServletResponse response, LoginConfig config)
    throws IOException
  {
    Principal principal = request.getUserPrincipal();
    if (principal != null)
    {
      String ssoId = (String)request.getNote("org.apache.catalina.request.SSOID");
      if (ssoId != null) {
        associate(ssoId, request.getSessionInternal(true));
      }
      return true;
    }
    X509Certificate[] certs = request.getCertificateChain();
    if ((certs == null) || (certs.length < 1))
    {
      if (authenticateBasic(request, response, config))
      {
        CatalinaLogger.AUTH_LOGGER.warn("AUTHENTICATION SUCCEEDED using basic, returning true...");
        
        return true;
      }
      CatalinaLogger.AUTH_LOGGER.warn("AUTHENTICATION FAILED using basic");
      if (getContainer().getLogger().isDebugEnabled()) {
        getContainer().getLogger().debug("  No certificates included with this request");
      }
      response.sendError(401, CatalinaMessages.MESSAGES.missingRequestCertificate());
      
      return false;
    }
    principal = this.context.getRealm().authenticate(certs);
    if (principal == null)
    {
      if (getContainer().getLogger().isDebugEnabled()) {
        getContainer().getLogger().debug("  Realm.authenticate() returned false");
      }
      response.sendError(401, CatalinaMessages.MESSAGES.certificateAuthenticationFailure());
      
      return false;
    }
    register(request, response, principal, "CLIENT_CERT", null, null);
    
    return true;
  }
}

