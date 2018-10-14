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
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import java.util.Base64;

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
		 
		/**Sender assembles claims payload and encrypt**/
		  
		JwtClaims claims = new JwtClaims();
		claims.setIssuer("Issuer");	// who creates the token and signs it
		claims.setAudience("RealInfo");	// to whom the token is intended to be sent
		claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
		claims.setGeneratedJwtId();	// a unique identifier for the token
		claims.setIssuedAtToNow();	// when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(2);	// time before which the token is not yet valid (2 minutes ago)
		claims.setSubject("demo");
		
		claims.setClaim("email", "test@altusgroup.com");
		List<String> data = Arrays.asList("test", "test2", "test3");
		claims.setStringListClaim("data", data);
		System.out.println("Senders side :: " + claims.toJson());
		 
		//ENCRYPTING
		 
		//RSA_OAEP_256
		//Sender will get this public key from the receiver
		RsaJsonWebKey ceKey = RsaJwkGenerator.generateJwk(2048);
		PublicKey receipentPubKey = ceKey.getPublicKey();
		
		PublicKey PublicKeyFromKeyFile = getPublicKey(publicKeyPath);
		PrivateKey PrivateKeyFromKeyFile = getPrivateKey(privateKeyPath);
		
		
		//public key
		System.out.println("RSA public key: " +receipentPubKey.toString());
		System.out.println("RSA public key from file: " +PublicKeyFromKeyFile.toString());
		 
		//Generation of content encryption key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey contentEncryptKey = keyGen.generateKey();
		
		//Set JOSE header, JWE Encrypted Key, Initialization Vector, Ciphertext, Authentication Tag
		JsonWebEncryption jwe = new JsonWebEncryption();
		//jwe.setKey(receipentPubKey);
		jwe.setKey(PublicKeyFromKeyFile);
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		jwe.setContentEncryptionKey(contentEncryptKey.getEncoded());
		jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		//Setting Initial Vector = Optional as adding more randomness to the key
		/*SecureRandom iv = SecureRandom.getInstance("SHA1PRNG");
		jwe.setIv(iv.generateSeed(32));*/
		jwe.setPayload(claims.toJson());
		
		//Compact Serialization
		String encryptedJwt = jwe.getCompactSerialization();
		System.out.println("Encrypted ::" + encryptedJwt);
		
		       
		// Encode data on your side using BASE64
		byte[] encodedBytes = Base64.getEncoder().encode(encryptedJwt.getBytes());
		System.out.println("encodedBytes " + new String(encodedBytes));
		    
		 
	    /***************************RECEIVER'S END ***********************************/
		 
		// Decode data on other side, by processing encoded data
		byte[] decodedBytes = Base64.getDecoder().decode(encodedBytes);
		System.out.println("decodedBytes " + new String(decodedBytes));
		 
	    //Decrypt Ciphertext with JWE encrypted key
		JwtConsumer consumer = new JwtConsumerBuilder()
		                        .setExpectedAudience("RealInfo")
		                        .setExpectedIssuer("Issuer")
		                        .setRequireSubject()
		                        //.setDecryptionKey(ceKey.getPrivateKey())
		                        .setDecryptionKey(PrivateKeyFromKeyFile)
		                        .setDisableRequireSignature()
		                        .build();		
	
		JwtClaims receivedClaims = consumer.processToClaims(encryptedJwt);
		System.out.println("SUCESS :: JWT Validation :: " + receivedClaims);
         
    }	
}
