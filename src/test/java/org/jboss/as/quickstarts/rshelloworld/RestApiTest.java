package org.jboss.as.quickstarts.rshelloworld;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashSet;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.TokenUtil;

public class RestApiTest {
	
	int TOKEN_EXPIRATION_TIME = 300;
    
    @Test
    public void testXml() {
    	String type = "xml";
    	String user = "admin";
        System.out.println("***** Testing with type " + type + " and user " + user );
        
    	makeRequest(type, user, false);
    }
    
    @Test
    public void testXmlExpired() {
    	String type = "xml";
    	String user = "admin";
        System.out.println("***** Testing expired token with type " + type + " and user " + user );
        
    	makeRequest(type, user, true);
    }
    
    @Test
    public void testJson() {
    	String type = "json";
    	String user = "user";
        System.out.println("***** Testing with type " + type + " and user " + user );
        
    	makeRequest(type, user, false);
    }
    
    public void makeRequest(String jsonOrXml, String role, boolean useExpiredToken) {
    	Client client = ClientBuilder.newClient();
        WebTarget target = client.target("http://localhost:8080").path("/helloworld-rs").path("/rest").path("/" + jsonOrXml);
        
        String accessToken = null;
		try {
			if(useExpiredToken)
				accessToken = getExpiredAccessToken(role);
			else
				accessToken = getValidAccessToken(role);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
        System.out.println("***** " + accessToken);
        
        Response response = target.request(jsonOrXml.equals("json") ? MediaType.APPLICATION_JSON : MediaType.APPLICATION_XML)
        						.header("Authorization", "Bearer " + accessToken).get();
		
        
        System.out.println("***** Status code: " + response.getStatus());
        System.out.println("***** Status code: " + response.toString());
        
    }

    private PrivateKey readPrivateKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("private.pem");
        PemReader privateKeyReader = new PemReader(new InputStreamReader(is));
        try {
            PemObject privObject = privateKeyReader.readPemObject();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privObject.getContent());
            PrivateKey privateKey = factory.generatePrivate(privKeySpec);
            return privateKey;
        } finally {
            privateKeyReader.close();
        }
    }
    
    private String createAccessToken(String role, int issuedAt) throws Exception {
        AccessToken token = new AccessToken();
        token.type(TokenUtil.TOKEN_TYPE_BEARER);
        token.subject("testuser");
        token.issuedAt(issuedAt);
        token.issuer("https://rhsso:8443/auth/realms/helloworld-rs-jwt");
        token.expiration(issuedAt + TOKEN_EXPIRATION_TIME);
        token.setAllowedOrigins(new HashSet<>());

        AccessToken.Access access = new AccessToken.Access();
        token.setRealmAccess(access);
        access.addRole(role);

        Algorithm jwsAlgorithm = Algorithm.RS256;
        PrivateKey privateKey = readPrivateKey();
        String encodedToken = new JWSBuilder().type("JWT").jsonContent(token).sign(jwsAlgorithm, privateKey);
        return encodedToken;
    }
    
    private String getValidAccessToken(String role) throws Exception {
        return createAccessToken(role, (int) (System.currentTimeMillis() / 1000));
    }
    
    private String getExpiredAccessToken(String role) throws Exception {
        return createAccessToken(role, (int) (System.currentTimeMillis() / 1000) - TOKEN_EXPIRATION_TIME - 1);
    }

}
