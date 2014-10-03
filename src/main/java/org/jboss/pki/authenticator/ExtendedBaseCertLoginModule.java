package org.jboss.pki.authenticator;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import org.jboss.security.PicketBoxLogger;
import org.jboss.security.PicketBoxMessages;
import org.jboss.security.auth.callback.ObjectCallback;
import org.jboss.security.auth.spi.BaseCertLoginModule;

public class ExtendedBaseCertLoginModule
  extends BaseCertLoginModule
{
  protected Object[] getAliasAndCert()
    throws LoginException
  {
  PicketBoxLogger.LOGGER.traceBeginGetAliasAndCert();
    Object[] info = { null, null };
    if (this.callbackHandler == null) {
      throw PicketBoxMessages.MESSAGES.noCallbackHandlerAvailable();
    }
    NameCallback nc = new NameCallback("Alias: ");
    ObjectCallback oc = new ObjectCallback("Certificate: ");
    Callback[] callbacks = { nc, oc };
    String alias = null;
    X509Certificate cert = null;
    try
    {
     this.callbackHandler.handle(callbacks);
      alias = nc.getName();
      Object tmpCert = oc.getCredential();
      if (tmpCert != null)
      {
      if ((tmpCert instanceof X509Certificate))
        {
          cert = (X509Certificate)tmpCert;
          PicketBoxLogger.LOGGER.traceCertificateFound(cert.getSerialNumber().toString(16), cert.getSubjectDN().getName());
        }
        else if ((tmpCert instanceof X509Certificate[]))
        {
          X509Certificate[] certChain = (X509Certificate[])tmpCert;
          if (certChain.length > 0) {
            cert = certChain[0];
          }
        }
        else
        {
          throw PicketBoxMessages.MESSAGES.unableToGetCertificateFromClass(tmpCert != null ? tmpCert.getClass() : null);
        }
        System.out.print(">>>> BASECERTLOGINMOD - Getting SAN From CERT.");
        
        System.err.print(">>>> BASECERTLOGINMOD - Getting SAN From CERT.");
        
        alias = getSANFromCert(cert);
        PicketBoxLogger.LOGGER.traceInsertedCacheInfo(">>>> BASECERTLOGINMOD - Got SAN From CERT:" + alias);
        

        System.err.print(">>>> BASECERTLOGINMOD - Got SAN From CERT:" + alias);
      }
      else
      {
        PicketBoxLogger.LOGGER.warnNullCredentialFromCallbackHandler();
      }
    }
    catch (IOException e)
    {
      LoginException le = PicketBoxMessages.MESSAGES.failedToInvokeCallbackHandler();
      
      le.initCause(e);
      throw le;
    }
    catch (UnsupportedCallbackException uce)
   {
      LoginException le = new LoginException();
      le.initCause(uce);
      throw le;
    }
    info[0] = alias;
    info[1] = cert;
    PicketBoxLogger.LOGGER.traceEndGetAliasAndCert();
    return info;
  }
   
  protected String getSANFromCert(X509Certificate clientCert)
  {
    PKICertParser pkcp = new PKICertParser(clientCert);
    String subjAltName = pkcp.getSubjectAltName();
    
    int Uindx = subjAltName.indexOf('U');
    int eqlsIndx = subjAltName.indexOf('=');
    
    PicketBoxLogger.LOGGER.traceInsertedCacheInfo(">>>> BASECERTLOGINMOD - 1 Got SAN From CERT:" + subjAltName);
    

    subjAltName = subjAltName.substring(eqlsIndx + 1, subjAltName.length() - 1);
    
    int commaIndex = subjAltName.indexOf(",");
    if (commaIndex > 0)
    {
      subjAltName = subjAltName.substring(0, commaIndex);
      PicketBoxLogger.LOGGER.traceInsertedCacheInfo(">>>> BASECERTLOGINMOD - UPDATED Got SAN From CERT:" + subjAltName);
    }
     return subjAltName;
  }
}



/* Location:           C:\Users\RHC-R9L4HMR\Documents\EAP6\JBCT_JBossExtensions.jar
 *
 *  * Qualified Name:     mil.disa.gccs.jbct.jboss.extensions.ExtendedBaseCertLoginModule
 *
 *   * JD-Core Version:    0.7.0.1
 *
 *    */
