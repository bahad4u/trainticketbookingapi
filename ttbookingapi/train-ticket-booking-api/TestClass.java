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

   package com.example.requestpayload.batch.writer.factset;

import com.example.requestpayload.dto.factset.FactsetProcessedSecurityItem; // Simple DTO (Input)
import com.example.requestpayload.dto.factset.FactsetFinalPayload;    // Final JSON structure DTO (Output)
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.batch.item.Chunk;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemStreamException;
import org.springframework.batch.item.ItemStreamWriter;
import org.springframework.batch.core.StepExecution; // To get context
import org.springframework.batch.core.annotation.BeforeStep; // To hook into step lifecycle
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value; // For field injection

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ItemStreamWriter for Factset.
 * Aggregates primary identifiers during the write phase from simple FactsetProcessedSecurityItem DTOs.
 * In the close() method, it builds the final FactsetFinalPayload JSON structure
 * (using aggregated IDs and formulas retrieved from StepExecutionContext)
 * and writes it to a single file in the configured temporary directory.
 * This writer produces the final aggregated JSON template.
 */
public class FactsetJsonPayloadWriter implements ItemStreamWriter<FactsetProcessedSecurityItem> {

    private static final Logger log = LoggerFactory.getLogger(FactsetJsonPayloadWriter.class);

    // Inject directory path directly from configuration properties
    @Value("${batch.output.temp.directory:./data/temp}")
    private String dataTempDirectory;

    // Dependencies injected via constructor
    private final String clientRequestIdentifier;
    private final ObjectMapper objectMapper;

    // --- State variables managed across chunks ---
    private Path outputFilePath;
    private List<String> collectedIds;
    private String determinedUniverseType;
    // To store formulas retrieved from context in beforeStep
    private Map<String, String> stepFormulasMap = Collections.emptyMap();


    /**
     * Constructor - Inject Job parameters and essential services like ObjectMapper.
     * dataTempDirectory is injected via @Value on the field.
     */
    public FactsetJsonPayloadWriter(String clientRequestIdentifier, ObjectMapper objectMapper) {
        this.clientRequestIdentifier = clientRequestIdentifier;
        // Recommend injecting a pre-configured ObjectMapper bean
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        log.debug("FactsetJsonPayloadWriter instance created for Req ID: {}", clientRequestIdentifier);
    }

    /**
     * Retrieves formulas from StepExecutionContext before the step begins processing items.
     * Requires a StepExecutionListener (e.g., FactsetStepListener) to have run
     * and populated the context with the key "factsetFormulas".
     */
    @BeforeStep
    public void retrieveFormulasFromContext(StepExecution stepExecution) {
        log.debug("FactsetJsonPayloadWriter @BeforeStep: Retrieving formulas from StepExecutionContext.");
        ExecutionContext stepContext = stepExecution.getExecutionContext();
        // Use the same key the listener used to store the formulas
        Object formulasObject = stepContext.get("factsetFormulas");

        if (formulasObject instanceof Map) {
            try {
                // Attempt a safe cast to the expected Map type
                @SuppressWarnings("unchecked")
                Map<String, String> fetchedMap = (Map<String, String>) formulasObject;
                // Store a copy to prevent potential modification issues if context object is mutable? Or trust listener.
                this.stepFormulasMap = new HashMap<>(fetchedMap); // Store safely
                log.info("Successfully retrieved {} formulas from step context.", this.stepFormulasMap.size());
            } catch (ClassCastException e) {
                 log.error("Object found in StepExecutionContext under key 'factsetFormulas' could not be cast to Map<String, String>: {}", formulasObject.getClass().getName(), e);
                 this.stepFormulasMap = Collections.emptyMap();
            }
        } else {
            if (formulasObject == null) {
                log.warn("No formulas found in StepExecutionContext under key 'factsetFormulas'. Final output might have missing/placeholder formulas.");
            } else {
                log.error("Object found in StepExecutionContext under key 'factsetFormulas' is not a Map<String, String>: {}", formulasObject.getClass().getName());
            }
            this.stepFormulasMap = Collections.emptyMap(); // Default to empty
        }
    }

    /**
     * Initializes internal state (lists) and determines output file path.
     * Creates the output directory if necessary. Does NOT open the file stream yet.
     */
    @Override
    public void open(ExecutionContext executionContext) throws ItemStreamException {
        log.debug("Opening state for FactsetJsonPayloadWriter.");
        // Initialize aggregation lists
        this.collectedIds = new ArrayList<>();
        this.determinedUniverseType = "UNKNOWN"; // Default value, updated in write

        // Ensure injected values are present before proceeding
        if (dataTempDirectory == null || dataTempDirectory.isBlank()) {
            throw new ItemStreamException("Temporary data directory path (@Value) is not set or empty.");
        }
        if (clientRequestIdentifier == null || clientRequestIdentifier.isBlank()) {
            throw new ItemStreamException("Client Request Identifier is null or blank.");
        }

        // Define output path - use .json extension for the final aggregated file
        this.outputFilePath = Paths.get(dataTempDirectory, clientRequestIdentifier + ".json");

        try {
            // Ensure the parent directory exists
            Files.createDirectories(outputFilePath.getParent());
             // Delete existing file on open to ensure clean output for this run
             Files.deleteIfExists(this.outputFilePath);
             log.debug("Deleted existing file if present: {}", this.outputFilePath.getFileName());
        } catch (IOException e) {
            throw new ItemStreamException("Failed to prepare output directory or delete existing file: " + outputFilePath.getParent(), e);
        }
        log.info("Output file target set to: {}", outputFilePath.toAbsolutePath());
    }

    /**
     * Processes a chunk of simple items: Aggregates IDs and determines universe type.
     * Does NOT write to the file here.
     */
    @Override
    public void write(Chunk<? extends FactsetProcessedSecurityItem> chunk) throws Exception {
        log.trace("Processing chunk of {} items for aggregation.", chunk.getItems().size());

        for (FactsetProcessedSecurityItem item : chunk.getItems()) {
            if (item == null) continue;

            // 1. Collect Primary ID (ensure uniqueness)
            if (item.getPrimaryIdentifier() != null && !item.getPrimaryIdentifier().isBlank()) {
                if (!this.collectedIds.contains(item.getPrimaryIdentifier())) {
                     this.collectedIds.add(item.getPrimaryIdentifier());
                }
            }

            // 2. Determine Universe Type (use the first non-blank/non-unknown one found)
            if (this.determinedUniverseType.equals("UNKNOWN")) {
                 if (item.getInstrumentType() != null && !item.getInstrumentType().isBlank()) {
                     this.determinedUniverseType = item.getInstrumentType();
                     log.trace("Determined universeType as: {}", this.determinedUniverseType);
                 }
            }
        }
        log.trace("Collected IDs count after chunk: {}", this.collectedIds.size());
    }

    /**
     * Called after all chunks are processed by the step.
     * Builds the final FactsetFinalPayload JSON structure using aggregated data
     * and formulas from the context, then writes it to the single output file.
     */
    @Override
    public void close() throws ItemStreamException {
        log.info("Close called for FactsetJsonPayloadWriter. Aggregating and writing final JSON. Total unique IDs collected: {}",
            (this.collectedIds != null ? this.collectedIds.size() : 0));

        // --- Build Final Payload DTO ---
        FactsetFinalPayload finalPayload = new FactsetFinalPayload();
        FactsetFinalPayload.PayloadData payloadData = finalPayload.getData(); // Access inner data object

        // Set aggregated IDs
        payloadData.setIds(this.collectedIds == null ? Collections.emptyList() : this.collectedIds); // Assign collected list (already unique)

        // Set determined universe type
        payloadData.setUniverseType(this.determinedUniverseType);

        // Set formulas (filtered/ordered based on hardcoded display names in DTO)
        List<String> targetDisplayNames = payloadData.getDisplayName(); // Get target list from DTO
        Map<String, String> formulasSourceMap = this.stepFormulasMap; // Use map fetched in beforeStep

        if (formulasSourceMap.isEmpty()) {
             log.warn("Formula map from context was empty. Formulas in output will be placeholders/defaults.");
        }

        // Create the final ordered list of formulas based on the target display names
        List<String> orderedFormulas = targetDisplayNames.stream()
            .map(displayName -> formulasSourceMap.getOrDefault(
                    displayName.trim(), // Trim display name from target list
                    "FORMULA_NOT_FOUND_FOR_" + displayName.trim().replace(" ","_")) // Placeholder if not found
            )
            .collect(Collectors.toList());
        payloadData.setFormulas(orderedFormulas);

        // Constants like calendar, fsymId, etc., are set by DTO defaults in FactsetFinalPayload

        // --- Serialize Final Payload to JSON String ---
        String jsonOutput;
        try {
            // Use the injected ObjectMapper
            jsonOutput = this.objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(finalPayload); // Use pretty print
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize final Factset payload for request ID {}", clientRequestIdentifier, e);
            throw new ItemStreamException("Failed to serialize final JSON payload", e);
        }

        // --- Write Single JSON String to Output File ---
        log.info("Attempting to write final aggregated JSON ({} bytes) to: {}", jsonOutput.length(), outputFilePath.toAbsolutePath());
        // Use try-with-resources to ensure the writer is closed properly
        try (BufferedWriter fileWriter = Files.newBufferedWriter(outputFilePath,
                                                                  StandardOpenOption.CREATE,           // Create
                                                                  StandardOpenOption.TRUNCATE_EXISTING,  // Overwrite
                                                                  StandardOpenOption.WRITE))         // Open for writing
        {
            fileWriter.write(jsonOutput);
            log.info("Successfully wrote final aggregated JSON to {}", outputFilePath.toAbsolutePath());
        } catch (IOException e) {
            log.error("Error writing final aggregated JSON payload to file: {}", outputFilePath.toAbsolutePath(), e);
            throw new ItemStreamException("Failed to write final JSON payload to file", e);
        } finally {
            // Clean up internal state
            this.collectedIds = null;
            this.stepFormulasMap = null;
            this.determinedUniverseType = null;
        }
    }

    /**
     * No specific state update needed here unless implementing complex restart for aggregation.
     */
    @Override
    public void update(ExecutionContext executionContext) throws ItemStreamException {
        log.trace("ItemStreamWriter update called.");
    }
}              

============================================================================================

    public void afterJob(JobExecution jobExecution) {
        String clientRequestIdentifier = jobExecution.getJobParameters().getString("clientRequestIdentifier");
        String jobName = jobExecution.getJobInstance().getJobName();
        BatchStatus jobStatus = jobExecution.getStatus();
        ExitStatus jobExitStatus = jobExecution.getExitStatus();

        log.info("========================================================================");
        log.info("Finished Factset Job: {} (Instance ID: {}, Execution ID: {})", jobName, jobExecution.getJobInstance().getInstanceId(), jobExecution.getId());
        log.info("  Status: {}, Exit Status: {}", jobStatus, jobExitStatus.getExitCode());
        log.info("  Start Time: {}, End Time: {}", jobExecution.getStartTime(), jobExecution.getEndTime());
        // ... [Optional: Duration, Step Summaries logging] ...

        // --- Save/Move the output file IF job completed successfully ---
        if (jobStatus == BatchStatus.COMPLETED) {
            log.info("Job completed successfully. Attempting to process output file...");

            if (clientRequestIdentifier == null || clientRequestIdentifier.isBlank()) {
                 log.error("Cannot process output file: clientRequestIdentifier is missing from Job Parameters.");
                 // Potentially update DB status to reflect this post-processing error
                 jobExecution.setExitStatus(ExitStatus.FAILED.addDescription("Missing clientRequestIdentifier for post-processing")); // Modify exit status
                 // Update final status below will reflect FAILED
            } else if (dataTempDirectory == null || dataTempDirectory.isBlank()) {
                 log.error("Cannot process output file: Temporary data directory is missing.");
                 jobExecution.setExitStatus(ExitStatus.FAILED.addDescription("Missing temp directory for post-processing"));
            } else {
                // Construct the path to the file expected to be created by the writer
                Path tempFilePath = Paths.get(dataTempDirectory, clientRequestIdentifier + ".json"); // .json extension

                log.info("Checking for final output file at: {}", tempFilePath.toAbsolutePath());
                if (Files.exists(tempFilePath)) {
                    log.info("Output file found. Calling FileService.saveFinalPayloadFile...");
                    try {
                        // --- Call your FileService ---
                        boolean saved = fileService.saveFinalPayloadFile(tempFilePath, clientRequestIdentifier + ".json");

                        if (saved) {
                            log.info("FileService successfully saved/processed file for request ID: {}", clientRequestIdentifier);
                            // Delete temp file *only* if save/move was successful and didn't already delete it
                            try {
                                Files.deleteIfExists(tempFilePath);
                                log.info("Deleted temporary file: {}", tempFilePath.getFileName());
                            } catch (IOException e) {
                                log.warn("Could not delete temporary file: {}", tempFilePath.getFileName(), e);
                            }
                        } else {
                            log.error("FileService reported failure processing file for request ID: {}", clientRequestIdentifier);
                            jobExecution.setExitStatus(ExitStatus.FAILED.addDescription("FileService failed to save payload"));
                        }
                    } catch (Exception e) {
                         log.error("Error occurred while calling FileService or handling file for request ID {}: {}", clientRequestIdentifier, tempFilePath.toAbsolutePath(), e);
                         jobExecution.setExitStatus(ExitStatus.FAILED.addDescription("Error during file saving: " + e.getMessage()));
                    }
                } else {
                    log.error("Output file NOT FOUND at expected location: {}. File could not be saved.", tempFilePath.toAbsolutePath());
                    jobExecution.setExitStatus(ExitStatus.FAILED.addDescription("Expected output file not found after step completion"));
                }
            }
        } else {
            log.error("Job did not complete successfully (Status: {}). Final file processing skipped.", jobStatus);
            jobExecution.getFailureExceptions().forEach(ex -> log.error("  Failure Exception: ", ex));
        }

        // --- Final Status Update ---
        try {
             String finalStatus = jobExecution.getStatus() == BatchStatus.COMPLETED && jobExecution.getExitStatus().getExitCode().equals(ExitStatus.COMPLETED.getExitCode())
                                  ? "JOB_COMPLETED" : "JOB_FAILED";
             // TODO: Implement DB status update
             // statusUpdateService.updateStatus(clientRequestIdentifier, finalStatus, jobExecution.getExitStatus().getExitDescription());
             log.info("Placeholder: Updated final status for request ID {} to {}.", clientRequestIdentifier, finalStatus);
         } catch (Exception e) {
             log.error("Failed to update final job status for request ID {}", clientRequestIdentifier, e);
         }
        log.info("========================================================================");
        // Note: The listener doesn't return an ExitStatus itself, it modifies the JobExecution's status if needed.
    }

==========================================================
