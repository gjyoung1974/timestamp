package com.goyoung.crypto.pki.timestamp.authenticode.servlet;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

public class GenTimeStamp {

	public static byte[] Generate(String webpath, String requestbytes) throws IOException, OperatorCreationException, CMSException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		
		Security.addProvider(new BouncyCastleProvider());
		
		//TODO we use a PKCS11 library here:
		File file=new File(webpath + "/timestamp_signer.p12");
		FileInputStream in=new FileInputStream(file);
		KeyStore rootP12keyStore = KeyStore.getInstance("PKCS12","BC");
		rootP12keyStore.load(in,"Password1!".toCharArray());
		in.close();
		
		//get the Private key and signer certificate from the default alias
		PrivateKey pk  = (PrivateKey) rootP12keyStore.getKey("mykey", "Password1!".toCharArray());
		Certificate p12Cert = rootP12keyStore.getCertificate("mykey");
		
		// create an array from the certificate chain
		ArrayList<Certificate> certList = new ArrayList<Certificate>();
		certList.add(p12Cert);
		//create a certificate array from the certificate chain
		Certificate[] certs = rootP12keyStore.getCertificateChain("mykey");//certList.toArray(new Certificate[0]);
		
		//create an ASN1Object from the timestampRequest base64 bytes:
		ASN1Primitive asn1obj = ASN1Primitive.fromByteArray(Base64.decode(requestbytes));
		ASN1Sequence asn1seq = ASN1Sequence.getInstance(asn1obj);

		//create an ASN1Object from the timestampRequest base64 bytes:
		ASN1Sequence asn1seq1 = ASN1Sequence.getInstance(asn1seq.getObjectAt(1));
		ASN1TaggedObject tag = ASN1TaggedObject.getInstance(asn1seq1.getObjectAt(1));
		
		//get tagged object's octet string into byte array:
		ASN1OctetString octets = ASN1OctetString.getInstance(tag.getObject());
		byte[] content = octets.getOctets();
		
		// instantiate a CMSSignedData signer:
		CMSSignedDataGenerator cmssdg = new CMSSignedDataGenerator();
		X509Certificate x509cert = (X509Certificate) certs[0];
		List<X509Certificate> certL = new ArrayList<X509Certificate>();

		//add all the certs in the array to the list..
		for (Certificate cert : certs) {
			certL.add((X509Certificate) cert);
		}

		Date date = new Date(); //get the current date

		//create a vector containing the signing time encoded as DerSet
		ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
		signedAttributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(date))));

		//instantiate an attributesTable
		AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
		signedAttributesTable.toASN1EncodableVector();
		DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);

		//generate attributes table
		SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
		signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);

		//instantiate content signer with SHA2 hash
		JcaContentSignerBuilder contentSigner = new JcaContentSignerBuilder("SHA256WithRSA");
		contentSigner.setProvider("BC");
		
		//configure our CMS signed data generator
		cmssdg.addSignerInfoGenerator(signerInfoBuilder.build(contentSigner.build(pk),new X509CertificateHolder(x509cert.getEncoded())));

		//instanciate a CertStore from our certlist and add to singed data generator
		JcaCertStore cs = new JcaCertStore(certList);
		cmssdg.addCertificates(cs);

		//type and sign the data:
		CMSTypedData cmspba = new CMSProcessableByteArray(content);
		CMSSignedData cmssd = cmssdg.generate(cmspba, true);

		//generate DER encoded TimestampResp
		byte[] der = ASN1Primitive.fromByteArray(cmssd.getEncoded()).getEncoded();

		//return the response as Base64 encoded text
		return Base64.encode(der);

	}
}
