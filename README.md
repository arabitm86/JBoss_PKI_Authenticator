# JBoss_PKI_Authenticator

 <security-domain name="other">
                       <authentication>
                               <login-module code="org.jboss.security.ClientLoginModule" flag="required"/>
                           <login-module code="Remoting" flag="optional">
                               <module-option name="password-stacking" value="useFirstPass"/>
                           </login-module>
                           <login-module code="org.jboss.security.auth.spi.LdapExtLoginModule" flag="optional">
                               <module-option name="password-stacking" value="useFirstPass"/>
                               <module-option name="java.naming.provider.url" value="ldap://hostname:3268"/>
                               <module-option name="java.naming.security.authentication" value="simple"/>
                               <!--<module-option name="java.naming.security.protocol" value="ssl"/>-->
                               <module-option name="java.naming.security.principal" value="CN=Directory Manager,OU=people,DC=se,DC=hr,DC=testing,DC=com"/>
                               <module-option name="java.naming.security.credentials" value="password"/>
                               <module-option name="baseCtxDN" value="DC=se,DC=hr,DC=testing,DC=com"/>
                               <module-option name="baseFilter" value="(userPrincipalName={0})"/>
                               <module-option name="rolesCtxDN" value="DC=se,DC=hr,DC=testing,DC=com"/>
                               <module-option name="roleFilter" value="(userPrincipalName={0})"/>
                               <module-option name="roleAttributeID" value="memberOf"/>
                               <module-option name="roleNameAttributeID" value="cn"/>
                               <module-option name="roleRecursion" value="0"/>
                               <module-option name="java.naming.referral" value="follow"/>
                               <module-option name="roleAttributeIsDN" value="True"/>
                               <module-option name="searchScope" value="SUBTREE_SCOPE"/>
                           </login-module>
                           <login-module code="mil.disa.gccs.jbct.jboss.extensions.ExtendedBaseCertLoginModule" flag="optional">
                               <module-option name="password-stacking" value="useFirstPass"/>
                               <module-option name="securityDomain" value="java:/jaas/other"/>
                               <module-option name="verifier" value="org.jboss.security.auth.certs.AnyCertVerifier"/>
                           </login-module>
                           <login-module name="org.jboss.security.auth.spi.LdapExtLoginModule-2" code="org.jboss.security.auth.spi.LdapExtLoginModule" flag="required">
                               <module-option name="password-stacking" value="useFirstPass"/>
                               <module-option name="java.naming.provider.url" value="ldap://hoostname:3268"/>
                               <module-option name="java.naming.security.authentication" value="simple"/>
                               <!--<module-option name="java.naming.security.protocol" value="ssl"/>-->
                               <module-option name="java.naming.security.principal" value="CN=Directory Manager,OU=people,DC=se,DC=hr,DC=testing,DC=com"/>
                               <module-option name="java.naming.security.credentials" value="password"/>
                               <module-option name="baseCtxDN" value="DC=se,DC=hr,DC=testing,DC=com"/>
                               <module-option name="baseFilter" value="(userPrincipalName={0})"/>
                               <module-option name="rolesCtxDN" value="DC=se,DC=hr,DC=testing,DC=com"/>
                               <module-option name="roleFilter" value="(userPrincipalName={0})"/>
                               <module-option name="roleAttributeID" value="memberOf"/>
                               <module-option name="roleNameAttributeID" value="cn"/>
                               <module-option name="roleRecursion" value="0"/>
                               <module-option name="java.naming.referral" value="follow"/>
                               <module-option name="roleAttributeIsDN" value="True"/>
                               <module-option name="searchScope" value="SUBTREE_SCOPE"/>
                           </login-module>
                       </authentication>
                       <jsse keystore-password="${VAULT::certificates::jks_file_name::1}" keystore-url="${jbct.keystore.file}" truststore-password="${VAULT::certificates::jks_file_name::1}" truststore-url="path_to_truststore.jks" client-auth="true"/>
                   </security-domain>
