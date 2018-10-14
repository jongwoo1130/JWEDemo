package jwe.demo.impl;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
 
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
 
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

public class JWTEncryption {
	private static String privateKeyPath = "keys/private_key.der";
	private static String publicKeyPath = "keys/public_key.der";
	
	public static PrivateKey getPrivateKey(String filename) throws Exception {	
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	
	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}
	
	
	public static PublicKey getPublicKey(String filename) throws Exception {
		    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePublic(spec);
	}
	
	public static void main(String[] args) throws Exception {
		 
		/******************** SENDER sample code **********************/
		  
		JwtClaims claims = new JwtClaims();
		claims.setIssuer("Issuer");	// who creates the token and signs it
		claims.setAudience("RealInfo");	// to whom the token is intended to be sent
		claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
		claims.setGeneratedJwtId();	// a unique identifier for the token
		claims.setIssuedAtToNow();	// when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(2);	// time before which the token is not yet valid (2 minutes ago)
		claims.setSubject("demo");
		
		claims.setClaim("email", "test@altusgroup.com");
		List<String> data = Arrays.asList("data1", "data2", "data3");
		claims.setStringListClaim("data", data);
		System.out.println("Senders side :: " + claims.toJson());
		 
		//ENCRYPTION
		 
		//RSA_OAEP_256
		PublicKey PublicKeyFromKeyFile = getPublicKey(publicKeyPath);
		PrivateKey PrivateKeyFromKeyFile = getPrivateKey(privateKeyPath);
		
		//Generation of content encryption key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey contentEncryptKey = keyGen.generateKey();
		
		//Set JOSE header, JWE Encrypted Key, Initialization Vector, Ciphertext, Authentication Tag
		JsonWebEncryption jwe = new JsonWebEncryption();
		
		//Set alg and enc in Header
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
		jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		
		jwe.setKey(PublicKeyFromKeyFile);
		jwe.setContentEncryptionKey(contentEncryptKey.getEncoded());
		
		//Set iv... Optional as adding more randomness to the key
		SecureRandom iv = SecureRandom.getInstance("SHA1PRNG");
		jwe.setIv(iv.generateSeed(32));
		
		//Set claims
		jwe.setPayload(claims.toJson());

		//Compact Serialization
		String encryptedJwt = jwe.getCompactSerialization();
		System.out.println("Encrypted ::" + encryptedJwt);
		    
		/******************** RECEIVER sample code **********************/ 
	    /**
	     * RECEIVER decrypts the CEK 
	     * and decrypts Ciphertext with CEK to produce claims
	     * **/
				 
	    //Decrypt Ciphertext with JWE encrypted key
		JwtConsumer consumer = new JwtConsumerBuilder()
		                        .setExpectedAudience("RealInfo")
		                        .setExpectedIssuer("Issuer")
		                        .setRequireSubject()
		                        .setDecryptionKey(PrivateKeyFromKeyFile)
		                        .setDisableRequireSignature()
		                        .build();		
	
		JwtClaims receivedClaims = consumer.processToClaims(encryptedJwt);
		System.out.println("SUCESS :: JWT Validation :: " + receivedClaims);         
    }	
}
