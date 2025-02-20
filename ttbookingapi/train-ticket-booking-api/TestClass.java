import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PKCEUtil {
    public static String generateCodeVerifier() {
            SecureRandom secureRandom = new SecureRandom();
                    byte[] codeVerifier = new byte[32]; // 32 bytes gives you a string length within the required range
                            secureRandom.nextBytes(codeVerifier);
                                    return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
                                        }

                                            public static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
                                                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                                                            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                                                                    return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                                                                        }
                                                                        }


public class OAuthPKCE {
    public static void main(String[] args) throws NoSuchAlgorithmException {
            String clientId = "your_client_id";
                    String redirectUri = "your_redirect_uri";
                            String authorizationEndpoint = "https://your-sso.com/oauth2/authorize";
                                    
                                            // Generate the code verifier and challenge
                                                    String codeVerifier = PKCEUtil.generateCodeVerifier();
                                                            String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

                                                                    // Build the authorization URL
                                                                            String authUrl = authorizationEndpoint + "?response_type=code"
                                                                                            + "&client_id=" + clientId
                                                                                                            + "&redirect_uri=" + redirectUri
                                                                                                                            + "&code_challenge=" + codeChallenge
                                                                                                                                            + "&code_challenge_method=S256"
                                                                                                                                                            + "&scope=openid profile email";

                                                                                                                                                                    // Redirect the user or open the URL in a browser
                                                                                                                                                                            System.out.println("Open this URL in a browser: " + authUrl);
                                                                                                                                                                                }
                                                                                                                                                                                }




import okhttp3.*;

import java.io.IOException;

public class TokenExchange {
    public static void exchangeCodeForToken(String authorizationCode, String codeVerifier) throws IOException {
            String tokenEndpoint = "https://your-sso.com/oauth2/token";
                    String clientId = "your_client_id";
                            String redirectUri = "your_redirect_uri";

                                    OkHttpClient client = new OkHttpClient();

                                            RequestBody formBody = new FormBody.Builder()
                                                            .add("grant_type", "authorization_code")
                                                                            .add("client_id", clientId)
                                                                                            .add("code", authorizationCode)
                                                                                                            .add("redirect_uri", redirectUri)
                                                                                                                            .add("code_verifier", codeVerifier)
                                                                                                                                            .build();

                                                                                                                                                    Request request = new Request.Builder()
                                                                                                                                                                    .url(tokenEndpoint)
                                                                                                                                                                                    .post(formBody)
                                                                                                                                                                                                    .header("Content-Type", "application/x-www-form-urlencoded")
                                                                                                                                                                                                                    .build();

                                                                                                                                                                                                                            Response response = client.newCall(request).execute();
                                                                                                                                                                                                                                    System.out.println(response.body().string());
                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                        }



import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Map;
import java.util.HashMap;

public class AuthorizationCodeReceiver {

    public static void main(String[] args) throws Exception {
        // Create an HTTP server listening on port 8080
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/callback", new CallbackHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("Listening on http://localhost:8080/callback");
        
        // The server will continue running, waiting for the redirect.
    }

    static class CallbackHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            URI requestUri = exchange.getRequestURI();
            String query = requestUri.getQuery();
            // Extract parameters from the query string
            Map<String, String> params = queryToMap(query);
            String authorizationCode = params.get("code");

            System.out.println("Authorization Code: " + authorizationCode);

            // Send a simple response to the browser
            String response = "Authorization code received. You can close this window.";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

        // Helper method to parse query parameters
        private Map<String, String> queryToMap(String query) {
            Map<String, String> result = new HashMap<>();
            if(query != null) {
                for (String param : query.split("&")) {
                    String[] entry = param.split("=");
                    if (entry.length > 1) {
                        result.put(entry[0], entry[1]);
                    } else {
                        result.put(entry[0], "");
                    }
                }
            }
            return result;
        }
    }
}

                                                                                                                                                                                                                                        
