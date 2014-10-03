package org.jboss.pki.authenticator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.provider.JDKDSAPublicKey;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class PKICertParser
{
  public static final int DIGITALSIGNATURE = 0;
  public static final int NONREPUDIATION = 1;
  public static final int KEYENCIPHERMENT = 2;
  public static final int DATAENCIPHERMENT = 3;
  public static final int KEYAGREEMENT = 4;
  public static final int KEYCERTSIGN = 5;
  public static final int CRLSIGN = 6;
  public static final int ENCIPHERONLY = 7;
  public static final int DECIPHERONLY = 8;
  public static final String[] KEYUSAGETEXTS = { "DIGITALSIGNATURE", "NONREPUDIATION", "KEYENCIPHERMENT", "DATAENCIPHERMENT", "KEYAGREEMENT", "KEYCERTSIGN", "CRLSIGN", "ENCIPHERONLY", "DECIPHERONLY" };
  public static final int ANYEXTENDEDKEYUSAGE = 0;
  public static final int SERVERAUTH = 1;
  public static final int CLIENTAUTH = 2;
  public static final int CODESIGNING = 3;
  public static final int EMAILPROTECTION = 4;
  public static final int IPSECENDSYSTEM = 5;
  public static final int IPSECTUNNEL = 6;
  public static final int IPSECUSER = 7;
  public static final int TIMESTAMPING = 8;
  public static final int SMARTCARDLOGON = 9;
  public static final int OCSPSIGNING = 10;
  public static final String[] EXTENDEDKEYUSAGEOIDSTRINGS = { "1.3.6.1.5.5.7.3.0", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6", "1.3.6.1.5.5.7.3.7", "1.3.6.1.5.5.7.3.8", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.9" };
  public static final String[] EXTENDEDKEYUSAGETEXTS = { "ANYEXTENDEDKEYUSAGE", "SERVERAUTH", "CLIENTAUTH", "CODESIGNING", "EMAILPROTECTION", "IPSECENDSYSTEM", "IPSECTUNNEL", "IPSECUSER", "TIMESTAMPING", "SMARTCARDLOGON", "OCSPSIGNER" };
  private static final int SUBALTNAME_OTHERNAME = 0;
  private static final int SUBALTNAME_RFC822NAME = 1;
  private static final int SUBALTNAME_DNSNAME = 2;
  private static final int SUBALTNAME_X400ADDRESS = 3;
  private static final int SUBALTNAME_DIRECTORYNAME = 4;
  private static final int SUBALTNAME_EDIPARTYNAME = 5;
  private static final int SUBALTNAME_URI = 6;
  private static final int SUBALTNAME_IPADDRESS = 7;
  private static final int SUBALTNAME_REGISTREDID = 8;
  public static final String UPN = "upn";
  public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
  public static final String GUID = "guid";
  public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
  private static DateFormat completedateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
  private static DateFormat simpledateFormat = new SimpleDateFormat("MM/dd/yyyy");
  private X509Certificate certificate;
  private X509Principal subjectdnfieldextractor;
  private X509Principal issuerdnfieldextractor;
  private String subjectaltnamestring;
  private String subjectdirattrstring;
  private static HashMap<String, String> extendedkeyusageoidtotextmap;
  
  public PKICertParser(X509Certificate certificate)
  {
    this.certificate = certificate;
    
    this.subjectdnfieldextractor = new X509Principal(certificate.getSubjectDN().getName());
    this.issuerdnfieldextractor = new X509Principal(certificate.getIssuerDN().getName());
    if (extendedkeyusageoidtotextmap == null)
    {
      extendedkeyusageoidtotextmap = new HashMap();
      for (int i = 0; i < EXTENDEDKEYUSAGETEXTS.length; i++) {
        extendedkeyusageoidtotextmap.put(EXTENDEDKEYUSAGEOIDSTRINGS[i], EXTENDEDKEYUSAGETEXTS[i]);
      }
    }
  }
  
  public String getSubjectAltName()
  {
    if (this.subjectaltnamestring == null) {
      try
      {
        Collection coll = this.certificate.getSubjectAlternativeNames();
        if (coll != null)
        {
          this.subjectaltnamestring = "";
          
          String separator = "";
          String guid = null;
          try
          {
            guid = getGuidAltName(this.certificate);
          }
          catch (IOException e)
          {
            this.subjectaltnamestring = e.getMessage();
          }
          if (guid != null)
          {
            this.subjectaltnamestring = (this.subjectaltnamestring + separator + "GUID=" + guid);
            separator = ", ";
          }
          String upn = null;
          try
          {
            upn = getUPNAltName(this.certificate);
          }
          catch (IOException e)
          {
            this.subjectaltnamestring = e.getMessage();
          }
          if (upn != null)
          {
            this.subjectaltnamestring = (this.subjectaltnamestring + separator + "UPN=" + upn);
            separator = ", ";
          }
          Iterator iter = coll.iterator();
          while (iter.hasNext())
          {
            List next = (List)iter.next();
            int OID = ((Integer)next.get(0)).intValue();
            switch (OID)
            {
            case 0: 
              Object obj = next.get(1);
              if (obj != null)
              {
                this.subjectaltnamestring = (this.subjectaltnamestring + separator + "OtherName=" + obj.toString());
                separator = ", ";
              }
              break;
            case 1: 
              this.subjectaltnamestring = (this.subjectaltnamestring + separator + "RFC822Name=" + (String)next.get(1));
              
              separator = ", ";
              break;
            case 2: 
              this.subjectaltnamestring = (this.subjectaltnamestring + separator + "DNSName=" + (String)next.get(1));
              
              separator = ", ";
              break;
            case 3: 
              break;
            case 5: 
              break;
            case 4: 
              break;
            case 6: 
              if (!this.subjectaltnamestring.equals("")) {
                this.subjectaltnamestring += ", ";
              }
              this.subjectaltnamestring = (this.subjectaltnamestring + separator + "URI=" + (String)next.get(1));
              
              separator = ", ";
              break;
            case 7: 
              this.subjectaltnamestring = (this.subjectaltnamestring + separator + "IPAddress=" + (String)next.get(1));
              
              separator = ", ";
            }
          }
        }
      }
      catch (CertificateParsingException e)
      {
        this.subjectaltnamestring = e.getMessage();
      }
    }
    return this.subjectaltnamestring;
  }
  
  public static String getGuidAltName(X509Certificate cert)
    throws IOException, CertificateParsingException
  {
    Collection altNames = cert.getSubjectAlternativeNames();
    if (altNames != null)
    {
      Iterator i = altNames.iterator();
      while (i.hasNext())
      {
        ASN1Sequence seq = getAltnameSequence((List)i.next());
        if (seq != null)
        {
          DERObjectIdentifier id = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
          if (id.getId().equals("1.3.6.1.4.1.311.25.1"))
          {
            ASN1TaggedObject obj = (ASN1TaggedObject)seq.getObjectAt(1);
            
            ASN1OctetString str = ASN1OctetString.getInstance(obj.getObject());
            
            return new String(Hex.encode(str.getOctets()));
          }
        }
      }
    }
    return null;
  }
  
  public static String getUPNAltName(X509Certificate cert)
    throws IOException, CertificateParsingException
  {
    Collection altNames = cert.getSubjectAlternativeNames();
    if (altNames != null)
    {
      Iterator i = altNames.iterator();
      while (i.hasNext())
      {
        ASN1Sequence seq = getAltnameSequence((List)i.next());
        String ret = getUPNStringFromSequence(seq);
        if (ret != null) {
          return ret;
        }
      }
    }
    return null;
  }
  
  private static String getUPNStringFromSequence(ASN1Sequence seq)
  {
    String retval = null;
    if (seq != null)
    {
      DERObjectIdentifier id = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
      
      debugPrint("PKICertParser.getUPNStringFromSequence id = " + id.toString());
      ASN1TaggedObject obj = (ASN1TaggedObject)seq.getObjectAt(1);
      
      ASN1TaggedObject innerObj = (ASN1TaggedObject)obj.getObject();
      DERUTF8String str = DERUTF8String.getInstance(innerObj, false);
      retval = str.getString();
      if (id.getId().equals("1.3.6.1.4.1.311.20.2.3"))
      {
        debugPrint("PKICertParser.getUPNStringFromSequence returning " + retval);
        return retval;
      }
      debugPrint("not UPN; id = " + id.getId() + "; value = " + retval);
      retval = null;
    }
    return retval;
  }
  
  private static ASN1Sequence getAltnameSequence(List listitem)
    throws IOException
  {
    Integer no = (Integer)listitem.get(0);
    if (no.intValue() == 0)
    {
      byte[] altName = (byte[])listitem.get(1);
      return getAltnameSequence(altName);
    }
    return null;
  }
  
  private static ASN1Sequence getAltnameSequence(byte[] value)
    throws IOException
  {
    ASN1Primitive oct = null;
    try
    {
      oct = new ASN1InputStream(new ByteArrayInputStream(value)).readObject();
    }
    catch (IOException e)
    {
      System.err.println("Error on getting Alt Name as a DERSEquence : " + e.getLocalizedMessage());
    }
    ASN1Sequence seq = ASN1Sequence.getInstance(oct);
    return seq;
  }
  
  public static String getKeyUsageAsText(X509Certificate certificate)
  {
    if (certificate == null) {
      return null;
    }
    String kuText = "";
    boolean[] keyusage = certificate.getKeyUsage();
    if (keyusage == null) {
      return "";
    }
    if (keyusage[0]) {
      kuText = kuText + "digitalSignature";
    }
    if (keyusage[1]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "nonRepudiation";
    }
    if (keyusage[2]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "keyEncipherment";
    }
    if (keyusage[3]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "dataEncipherment";
    }
    if (keyusage[4]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "keyAgreement";
    }
    if (keyusage[5]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "keyCertSign";
    }
    if (keyusage[6]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "cRLSign";
    }
    if (keyusage[7]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "encipherOnly";
    }
    if (keyusage[8]) {
      kuText = kuText + (kuText.equals("") ? "" : ", ") + "decipherOnly";
    }
    return kuText;
  }
  
  public static String getNSCertTypeAsText(X509Certificate certificate)
  {
    if (certificate == null) {
      return null;
    }
    byte[] nct = certificate.getExtensionValue(MiscObjectIdentifiers.netscapeCertType.getId());
    if (nct == null) {
      return "";
    }
    String nctText = "";
    if (nct[0] == 0) {
      nctText = nctText + "SSLClient";
    }
    if (nct[1] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "SSLServer";
    }
    if (nct[2] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "S/MIME";
    }
    if (nct[3] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "Object Signing";
    }
    if (nct[4] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "Reserved";
    }
    if (nct[5] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "SSL CA";
    }
    if (nct[6] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "S/MIME CA";
    }
    if (nct[7] == 0) {
      nctText = nctText + (nctText.equals("") ? "" : ", ") + "Object Signing CA";
    }
    return nctText;
  }
  
  public static String getExtendedKeyUsageAsText(X509Certificate certificate)
  {
    List extendedkeyusage = null;
    
    HashMap<String, String> extendedkeyusageoidtotextmap = null;
    String[] EXTENDEDKEYUSAGEOIDSTRINGS = { "2.5.29.37.0", "1.3.6.1.5.5.7.3.0", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6", "1.3.6.1.5.5.7.3.7", "1.3.6.1.5.5.7.3.8", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.9" };
    
    String[] EXTENDEDKEYUSAGETEXTS = { "All usages", "All usages", "Server authentication", "Client authentication", "Code signing", "Email protection", "IPSec end system", "IPSec tunnel", "IPSec user", "Timestamping", "Smartcard Logon", "OCSP signer" };
    
    extendedkeyusageoidtotextmap = new HashMap();
    for (int i = 0; i < EXTENDEDKEYUSAGETEXTS.length; i++) {
      extendedkeyusageoidtotextmap.put(EXTENDEDKEYUSAGEOIDSTRINGS[i], EXTENDEDKEYUSAGETEXTS[i]);
    }
    try
    {
      extendedkeyusage = certificate.getExtendedKeyUsage();
    }
    catch (CertificateParsingException e)
    {
      System.err.println("certificate parsing exception" + e.getLocalizedMessage());
      return null;
    }
    if (extendedkeyusage == null) {
      extendedkeyusage = new ArrayList();
    }
    String returnval = "";
    for (int i = 0; i < extendedkeyusage.size(); i++) {
      returnval = returnval + (returnval.equals("") ? "" : ", ") + (String)extendedkeyusageoidtotextmap.get(extendedkeyusage.get(i));
    }
    return returnval;
  }
  
  public static String getDNAsShortText(Principal dn)
  {
    X509Principal X509dn = new X509Principal(dn.getName());
    if (X509dn.getValues(X509Principal.CN).size() > 0) {
      return X509dn.getValues(X509Principal.CN).get(0).toString();
    }
    String str_dn = dn.getName();
    int last_equal = str_dn.lastIndexOf("=");
    if (last_equal >= 0) {
      return str_dn.substring(last_equal + 1, str_dn.length());
    }
    return str_dn;
  }
  
  public static String getNotBeforeAsText(X509Certificate certificate)
  {
    return simpledateFormat.format(certificate.getNotBefore());
  }
  
  public static String getNotBeforeAsFullText(X509Certificate certificate)
  {
    return completedateFormat.format(certificate.getNotBefore());
  }
  
  public static String getNotAfterAsText(X509Certificate certificate)
  {
    return simpledateFormat.format(certificate.getNotAfter());
  }
  
  public static String getNotAfterAsFullText(X509Certificate certificate)
  {
    return completedateFormat.format(certificate.getNotAfter());
  }
  
  public static String getPublicKeyInfo(PublicKey pk)
  {
    int keysize = 0;
    String format = pk.getAlgorithm();
    if ((pk instanceof RSAPublicKey))
    {
      RSAPublicKey rsapk = (RSAPublicKey)pk;
      keysize = (rsapk.getModulus().toByteArray().length - 1) * 8;
    }
    if ((pk instanceof JCEECPublicKey))
    {
      JCEECPublicKey ecpubkey = (JCEECPublicKey)pk;
      keysize = ecpubkey.getQ().getX().getFieldSize();
      
      format = "ECDSA";
    }
    if ((pk instanceof JDKDSAPublicKey))
    {
      JDKDSAPublicKey dsapubkey = (JDKDSAPublicKey)pk;
      keysize = dsapubkey.getY().bitLength();
    }
    return format + " " + keysize + "bits";
  }
  
  public static List<String> getSubjectAlternativeNames(X509Certificate certificate)
  {
    List<String> identities = new ArrayList();
    try
    {
      Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
      if (altNames == null) {
        return Collections.emptyList();
      }
      for (List item : altNames)
      {
        Integer type = (Integer)item.get(0);
        if (type.intValue() == 0) {
          try
          {
            ASN1InputStream decoder = new ASN1InputStream((byte[])item.toArray()[1]);
            ASN1Encodable encoded = decoder.readObject();
            encoded = ((DERSequence)encoded).getObjectAt(1);
            encoded = ((DERTaggedObject)encoded).getObject();
            encoded = ((DERTaggedObject)encoded).getObject();
            String identity = ((DERUTF8String)encoded).getString();
            
            identities.add(identity);
          }
          catch (UnsupportedEncodingException e)
          {
            System.err.println("Error decoding subjectAltName" + e.getLocalizedMessage());
          }
          catch (Exception e)
          {
            System.err.println("Error decoding subjectAltName" + e.getLocalizedMessage());
          }
        }
        System.err.println("Warning: SubjectAltName of invalid type found: " + certificate);
      }
    }
    catch (CertificateParsingException e)
    {
      System.err.println("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:" + e.getLocalizedMessage());
    }
    return identities;
  }
  
  public static String GeneralNameAsText(GeneralName gn)
  {
    StringBuffer buf = new StringBuffer();
    
    int tag = gn.getTagNo();
    ASN1Encodable obj = gn.getName();
    switch (tag)
    {
    case 1: 
      buf.append("rfc822Name=");
      buf.append(DERIA5String.getInstance(obj).getString());
      break;
    case 2: 
      buf.append("dNSName=");
      buf.append(DERIA5String.getInstance(obj).getString());
      break;
    case 6: 
      buf.append("URI=");
      buf.append(DERIA5String.getInstance(obj).getString());
      break;
    case 4: 
      buf.append("directoryName=");
      buf.append(X500Name.getInstance(obj).toString());
      break;
    case 5: 
      buf.append("ediPartyName=");
      buf.append(obj.toString());
      break;
    case 7: 
      buf.append("IP=");
      buf.append(obj.toString());
      break;
    case 0: 
      buf.append("otherName=");
      buf.append(obj.toString());
      break;
    case 8: 
      buf.append("registeredID=");
      buf.append(obj.toString());
      break;
    case 3: 
      buf.append("x400Address=");
      buf.append(obj.toString());
      break;
    default: 
      buf.append(gn.getTagNo());
      buf.append("=");
    }
    return buf.toString();
  }
  
  protected static void debugPrint(String message)
  {
    Date now = new Date();
    DateFormat df1 = DateFormat.getDateTimeInstance(2, 2);
    if (Boolean.getBoolean("mil.disa.ims.debugenabled")) {
      if (message != null) {
        System.out.println(df1.format(now) + ": PKICertParser" + " '" + message + "'");
      } else {
        System.out.println(df1.format(now) + ": PKICertParser" + " 'null'");
      }
    }
  }
}

