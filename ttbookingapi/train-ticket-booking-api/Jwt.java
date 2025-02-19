import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class VaultCertAuthExample {
        private static final String VAULT_ADDR = "https://your-vault-server:8200";
            private static final String JKS_PATH = "/path/to/client.jks";
                private static final String JKS_PASSWORD = "your-keystore-password";
                    private static final String VAULT_ROLE = "your-vault-role";
                        private static final String SECRET_PATH = "secret/your-sidecar-credentials";
                            private static final String DEV_SERVER_URL = "https://your-dev-server:443";

                                public static void main(String[] args) {
                                            try {
                                                            // 1. Configure Vault connection with JKS
                                                                        Vault vault = configureVaultWithJKS();
                                                                                    
                                                                                                // 2. Get sidecar credentials from Vault
                                                                                                            Credentials credentials = getSidecarCredentials(vault);
                                                                                                                        
                                                                                                                                    // 3. Create SSL context for dev server
                                                                                                                                                SSLContext devSSLContext = createDevSSLContext(credentials);
                                                                                                                                                            
                                                                                                                                                                        // 4. Connect to dev server
                                                                                                                                                                                    String response = callDevServer(devSSLContext);
                                                                                                                                                                                                System.out.println("Dev Server Response: " + response);
                                            } catch (Exception e) {
                                                            e.printStackTrace();
                                            }
                                }

                                    private static Vault configureVaultWithJKS() throws Exception {
                                                // Load JKS file
                                                        KeyStore keyStore = KeyStore.getInstance("JKS");
                                                                try (FileInputStream fis = new FileInputStream(JKS_PATH)) {
                                                                                keyStore.load(fis, JKS_PASSWORD.toCharArray());
                                                                }

                                                                        // Create SSL context from JKS
                                                                                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                                                                                        kmf.init(keyStore, JKS_PASSWORD.toCharArray());
                                                                                                SSLContext sslContext = SSLContext.getInstance("TLS");
                                                                                                        sslContext.init(kmf.getKeyManagers(), null, null);

                                                                                                                // Create HTTP client with custom SSL context
                                                                                                                        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                                                                                                                                            sslContext,
                                                                                                                                                            new String[]{"TLSv1.2", "TLSv1.3"},
                                                                                                                                                                            null,
                                                                                                                                                                                            SSLConnectionSocketFactory.getDefaultHostnameVerifier());

                                                                                                                                                                                                    CloseableHttpClient httpClient = HttpClients.custom()
                                                                                                                                                                                                                    .setSSLSocketFactory(sslSocketFactory)
                                                                                                                                                                                                                                    .build();

                                                                                                                                                                                                                                            // Configure Vault client
                                                                                                                                                                                                                                                    VaultConfig config = new VaultConfig()
                                                                                                                                                                                                                                                                    .address(VAULT_ADDR)
                                                                                                                                                                                                                                                                                    .httpClient(httpClient)
                                                                                                                                                                                                                                                                                                    .build();

                                                                                                                                                                                                                                                                                                            // Authenticate with Vault using certificate
                                                                                                                                                                                                                                                                                                                    Vault vault = new Vault(config);
                                                                                                                                                                                                                                                                                                                            AuthResponse authResponse = vault.auth().loginByCert(VAULT_ROLE);
                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                                                                                                            return new Vault(config.token(authResponse.getAuthClientToken()));
                                    }

                                        private static Credentials getSidecarCredentials(Vault vault) {
                                                    LogicalResponse response = vault.logical().read(SECRET_PATH);
                                                            return new Credentials(
                                                                                response.getData().get("certificate"),
                                                                                                response.getData().get("private_key")
                                                            );
                                        }

                                            private static SSLContext createDevSSLContext(Credentials credentials) throws Exception {
                                                        // Parse certificate and private key
                                                                X509Certificate cert = parseCertificate(Base64.getDecoder().decode(credentials.cert));
                                                                        PrivateKey privateKey = parsePrivateKey(Base64.getDecoder().decode(credentials.key));

                                                                                // Create PKCS12 keystore
                                                                                        KeyStore keyStore = KeyStore.getInstance("PKCS12");
                                                                                                keyStore.load(null, null);
                                                                                                        keyStore.setKeyEntry("sidecar", privateKey, "".toCharArray(), new Certificate[]{cert});

                                                                                                                // Initialize SSL context
                                                                                                                        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                                                                                                                                kmf.init(keyStore, "".toCharArray());
                                                                                                                                        
                                                                                                                                                SSLContext sslContext = SSLContext.getInstance("TLS");
                                                                                                                                                        sslContext.init(kmf.getKeyManagers(), null, null);
                                                                                                                                                                return sslContext;
                                            }

                                                private static String callDevServer(SSLContext sslContext) throws Exception {
                                                            HttpClient client = HttpClient.newBuilder()
                                                                            .sslContext(sslContext)
                                                                                            .build();

                                                                                                    HttpRequest request = HttpRequest.newBuilder()
                                                                                                                    .uri(URI.create(DEV_SERVER_URL + "/api/data"))
                                                                                                                                    .GET()
                                                                                                                                                    .build();

                                                                                                                                                            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                                                                                                                                                                    return response.body();
                                                }

                                                    private static X509Certificate parseCertificate(byte[] certBytes) throws Exception {
                                                                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                                                                        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
                                                    }

                                                        private static PrivateKey parsePrivateKey(byte[] keyBytes) throws Exception {
                                                                    try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(keyBytes)))) {
                                                                                    Object object = pemParser.readObject();
                                                                                                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                                                                                                            
                                                                                                                        if (object instanceof PEMKeyPair) {
                                                                                                                                            return converter.getKeyPair((PEMKeyPair) object).getPrivate();
                                                                                                                        } else if (object instanceof PrivateKeyInfo) {
                                                                                                                                            return converter.getPrivateKey((PrivateKeyInfo) object);
                                                                                                                        }
                                                                                                                                    throw new IllegalArgumentException("Unsupported private key format");
                                                                    }
                                                        }

                                                            private static class Credentials {
                                                                        final String cert;
                                                                                final String key;

                                                                                        Credentials(String cert, String key) {
                                                                                                        this.cert = cert;
                                                                                                                    this.key = key;
                                                                                        }
                                                            }
}import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class VaultCertAuthExample {
        private static final String VAULT_ADDR = "https://your-vault-server:8200";
            private static final String JKS_PATH = "/path/to/client.jks";
                private static final String JKS_PASSWORD = "your-keystore-password";
                    private static final String VAULT_ROLE = "your-vault-role";
                        private static final String SECRET_PATH = "secret/your-sidecar-credentials";
                            private static final String DEV_SERVER_URL = "https://your-dev-server:443";

                                public static void main(String[] args) {
                                            try {
                                                            // 1. Configure Vault connection with JKS
                                                                        Vault vault = configureVaultWithJKS();
                                                                                    
                                                                                                // 2. Get sidecar credentials from Vault
                                                                                                            Credentials credentials = getSidecarCredentials(vault);
                                                                                                                        
                                                                                                                                    // 3. Create SSL context for dev server
                                                                                                                                                SSLContext devSSLContext = createDevSSLContext(credentials);
                                                                                                                                                            
                                                                                                                                                                        // 4. Connect to dev server
                                                                                                                                                                                    String response = callDevServer(devSSLContext);
                                                                                                                                                                                                System.out.println("Dev Server Response: " + response);
                                            } catch (Exception e) {
                                                            e.printStackTrace();
                                            }
                                }

                                    private static Vault configureVaultWithJKS() throws Exception {
                                                // Load JKS file
                                                        KeyStore keyStore = KeyStore.getInstance("JKS");
                                                                try (FileInputStream fis = new FileInputStream(JKS_PATH)) {
                                                                                keyStore.load(fis, JKS_PASSWORD.toCharArray());
                                                                }

                                                                        // Create SSL context from JKS
                                                                                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                                                                                        kmf.init(keyStore, JKS_PASSWORD.toCharArray());
                                                                                                SSLContext sslContext = SSLContext.getInstance("TLS");
                                                                                                        sslContext.init(kmf.getKeyManagers(), null, null);

                                                                                                                // Create HTTP client with custom SSL context
                                                                                                                        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                                                                                                                                            sslContext,
                                                                                                                                                            new String[]{"TLSv1.2", "TLSv1.3"},
                                                                                                                                                                            null,
                                                                                                                                                                                            SSLConnectionSocketFactory.getDefaultHostnameVerifier());

                                                                                                                                                                                                    CloseableHttpClient httpClient = HttpClients.custom()
                                                                                                                                                                                                                    .setSSLSocketFactory(sslSocketFactory)
                                                                                                                                                                                                                                    .build();

                                                                                                                                                                                                                                            // Configure Vault client
                                                                                                                                                                                                                                                    VaultConfig config = new VaultConfig()
                                                                                                                                                                                                                                                                    .address(VAULT_ADDR)
                                                                                                                                                                                                                                                                                    .httpClient(httpClient)
                                                                                                                                                                                                                                                                                                    .build();

                                                                                                                                                                                                                                                                                                            // Authenticate with Vault using certificate
                                                                                                                                                                                                                                                                                                                    Vault vault = new Vault(config);
                                                                                                                                                                                                                                                                                                                            AuthResponse authResponse = vault.auth().loginByCert(VAULT_ROLE);
                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                                                                                                            return new Vault(config.token(authResponse.getAuthClientToken()));
                                    }

                                        private static Credentials getSidecarCredentials(Vault vault) {
                                                    LogicalResponse response = vault.logical().read(SECRET_PATH);
                                                            return new Credentials(
                                                                                response.getData().get("certificate"),
                                                                                                response.getData().get("private_key")
                                                            );
                                        }

                                            private static SSLContext createDevSSLContext(Credentials credentials) throws Exception {
                                                        // Parse certificate and private key
                                                                X509Certificate cert = parseCertificate(Base64.getDecoder().decode(credentials.cert));
                                                                        PrivateKey privateKey = parsePrivateKey(Base64.getDecoder().decode(credentials.key));

                                                                                // Create PKCS12 keystore
                                                                                        KeyStore keyStore = KeyStore.getInstance("PKCS12");
                                                                                                keyStore.load(null, null);
                                                                                                        keyStore.setKeyEntry("sidecar", privateKey, "".toCharArray(), new Certificate[]{cert});

                                                                                                                // Initialize SSL context
                                                                                                                        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                                                                                                                                kmf.init(keyStore, "".toCharArray());
                                                                                                                                        
                                                                                                                                                SSLContext sslContext = SSLContext.getInstance("TLS");
                                                                                                                                                        sslContext.init(kmf.getKeyManagers(), null, null);
                                                                                                                                                                return sslContext;
                                            }

                                                private static String callDevServer(SSLContext sslContext) throws Exception {
                                                            HttpClient client = HttpClient.newBuilder()
                                                                            .sslContext(sslContext)
                                                                                            .build();

                                                                                                    HttpRequest request = HttpRequest.newBuilder()
                                                                                                                    .uri(URI.create(DEV_SERVER_URL + "/api/data"))
                                                                                                                                    .GET()
                                                                                                                                                    .build();

                                                                                                                                                            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                                                                                                                                                                    return response.body();
                                                }

                                                    private static X509Certificate parseCertificate(byte[] certBytes) throws Exception {
                                                                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                                                                        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
                                                    }

                                                        private static PrivateKey parsePrivateKey(byte[] keyBytes) throws Exception {
                                                                    try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(keyBytes)))) {
                                                                                    Object object = pemParser.readObject();
                                                                                                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                                                                                                            
                                                                                                                        if (object instanceof PEMKeyPair) {
                                                                                                                                            return converter.getKeyPair((PEMKeyPair) object).getPrivate();
                                                                                                                        } else if (object instanceof PrivateKeyInfo) {
                                                                                                                                            return converter.getPrivateKey((PrivateKeyInfo) object);
                                                                                                                        }
                                                                                                                                    throw new IllegalArgumentException("Unsupported private key format");
                                                                    }
                                                        }

                                                            private static class Credentials {
                                                                        final String cert;
                                                                                final String key;

                                                                                        Credentials(String cert, String key) {
                                                                                                        this.cert = cert;
                                                                                                                    this.key = key;
                                                                                        }
                                                            }
}
                                                                                        }
                                                            }
                                                                                                                        }
                                                                                                                        }
                                                                    }
                                                        }
                                                    }
                                                }
                                            }
                                                            )
                                        }
                                                                                                                        )
                                                                }
                                    }
                                            }
                                            }
                                }
}
                                                                                        }
                                                            }
                                                                                                                        }
                                                                                                                        }
                                                                    }
                                                        }
                                                    }
                                                }
                                            }
                                                            )
                                        }
                                                                                                                        )
                                                                }
                                    }
                                            }
                                            }
                                }
}
