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
private static final Logger log = LoggerFactory.getLogger(FactsetServiceImpl.class);

    private final FactsetFeedTypeRepository feedTypeRepository;
    private final FormulaEntryRepository formulaRepository;

    // Constructor injection is preferred for mandatory dependencies
    @Autowired
    public FactsetServiceImpl(FactsetFeedTypeRepository feedTypeRepository,
                              FormulaEntryRepository formulaRepository) {
        this.feedTypeRepository = feedTypeRepository;
        this.formulaRepository = formulaRepository;
    }

    @Override
    @Transactional(readOnly = true) // Good practice for read operations
    public List<String> getDisplayNamesByFileType(String feedFileType) throws ServiceException {
        log.debug("Fetching display names for feedFileType: {}", feedFileType);
        if (feedFileType == null || feedFileType.isBlank()) {
            log.warn("feedFileType is null or blank, returning empty list.");
            return Collections.emptyList();
        }
        try {
            List<FactsetFeedTypeEntity> feedEntries = feedTypeRepository.findByFeedFileTypeIgnoreCase(feedFileType);

            if (feedEntries.isEmpty()) {
                log.warn("No display names found for feedFileType: {}", feedFileType);
                return Collections.emptyList();
            }

            List<String> displayNames = feedEntries.stream()
                    .map(FactsetFeedTypeEntity::getDisplayName)
                    .filter(name -> name != null && !name.isBlank()) // Ensure names are not blank
                    .distinct() // Get unique names
                    .collect(Collectors.toList());

            log.debug("Found {} unique display names for feedFileType {}", displayNames.size(), feedFileType);
            return displayNames;

        } catch (Exception e) {
            // Catch specific persistence exceptions if possible
            log.error("Database error fetching display names for feedFileType: {}", feedFileType, e);
            throw new ServiceException("Error fetching display names for feedFileType: " + feedFileType, e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, String> getFormulasByDisplayNames(List<String> displayNames) throws ServiceException {
        log.debug("Fetching formulas for {} display names", displayNames != null ? displayNames.size() : 0);
        if (displayNames == null || displayNames.isEmpty()) {
            return Collections.emptyMap();
        }

        try {
            // Fetch all potentially matching formulas in one query
            List<FormulaEntryEntity> formulaEntries = formulaRepository.findByDisplayNameIn(displayNames);

            if (formulaEntries.isEmpty()) {
                log.warn("No formulas found for the provided display names: {}", displayNames);
                return Collections.emptyMap();
            }

            // Convert list of entities to a Map<DisplayName, Formula>
            // Using Collectors.toMap - handles potential duplicate displayNames in DB gracefully (uses last one found)
            Map<String, String> formulaMap = formulaEntries.stream()
                    .filter(entry -> entry.getDisplayName() != null && entry.getFormula() != null) // Ensure fields aren't null
                    .collect(Collectors.toMap(
                            FormulaEntryEntity::getDisplayName, // Key = display name
                            FormulaEntryEntity::getFormula,   // Value = formula
                            (existingFormula, newFormula) -> newFormula // If duplicate display name, take the new one
                    ));

            log.debug("Created formula map with {} entries.", formulaMap.size());

            // Optional: Log which requested display names were NOT found
            if (log.isWarnEnabled() && formulaMap.size() < displayNames.size()) {
                 displayNames.forEach(requestedName -> {
                     if (!formulaMap.containsKey(requestedName)) {
                         log.warn("No formula found for requested display name: {}", requestedName);
                     }
                 });
            }

            return formulaMap;

        } catch (Exception e) {
            log.error("Database error fetching formulas for display names: {}", displayNames, e);
            throw new ServiceException("Error fetching formulas for display names", e);
        }
    }
==========================================================================================================
    private final ElasticsearchClient esClient;
    private final BulkIngester<Void> ingester; // Context is Void
    private final String indexName; // Target index for this instance

    /**
     * Constructor
     * @param esClient Injected ElasticsearchClient bean.
     * @param indexName The target Elasticsearch index (injected via @Value from job parameters).
     */
    // Use constructor injection (Autowired is optional on constructor if only one)
    public FactsetElasticsearchWriter(ElasticsearchClient esClient, String indexName) {
        this.esClient = Objects.requireNonNull(esClient, "ElasticsearchClient cannot be null");
        this.indexName = Objects.requireNonNull(indexName, "Target index name cannot be null");
        if (indexName.isBlank()) {
             throw new IllegalArgumentException("Target index name cannot be blank");
        }

        log.info("Initializing FactsetElasticsearchWriter for index: {}", this.indexName);

        // Initialize BulkIngester ONCE
        this.ingester = BulkIngester.of(b -> b
                .client(this.esClient)
                .maxOperations(1000) // Example: Max operations per bulk request
                .maxSize(5 * 1024 * 1024) // Example: Max total size 5MB
                .flushInterval(5, TimeUnit.SECONDS) // Example: Max time between flushes
                // TODO: Add listeners for detailed error handling/logging if needed
                // .listener(new BulkIngester.Listener<Void>() { ... })
        );
        log.info("BulkIngester initialized for Factset writer.");
    }

    @Override
    public void write(Chunk<? extends FactsetProcessedSecurityItem> chunk) throws Exception {
        int skippedCount = 0;
        int addedCount = 0;

        for (FactsetProcessedSecurityItem item : chunk.getItems()) {
            if (item == null) {
                skippedCount++;
                continue;
            }

            // --- Check skipCache flag ---
            if (item.isSkipCache()) {
                skippedCount++;
                log.trace("Skipping ES write for item with primaryId '{}' due to skipCache=true", item.getPrimaryIdentifier());
                continue;
            }

            // --- Get Payload and Identifiers ---
            JSONObject payload = item.getRequestPayLoad();
            String outputIndex = item.getOutputIndex(); // Get index from item (as per original BBG logic)
            String clientReqId = item.getClientRequestIdentifier();
            String primaryId = item.getPrimaryIdentifier();

            // --- Validate necessary data ---
            if (payload == null) {
                log.warn("Skipping item with primaryId '{}' because its requestPayload JSONObject is null.", primaryId);
                skippedCount++;
                continue;
            }
            if (outputIndex == null || outputIndex.isBlank()) {
                 log.warn("Skipping item with primaryId '{}' because its outputIndex is null or blank.", primaryId);
                 skippedCount++;
                 continue;
            }
             if (clientReqId == null || clientReqId.isBlank() || primaryId == null || primaryId.isBlank()) {
                 log.warn("Skipping item because clientRequestIdentifier or primaryIdentifier is missing. Payload: {}", payload.toString());
                 skippedCount++;
                 continue;
             }


            // --- Prepare Index Operation ---
            String docId = clientReqId + "_" + primaryId; // Construct document ID

            try {
                // Convert org.json.JSONObject to Map<String, Object> for ES Client
                // The ES Java Client's Jackson integration works best with Maps or POJOs.
                Map<String, Object> payloadMap = payload.toMap();

                IndexOperation<Map<String, Object>> indexOp = IndexOperation.of(idx -> idx
                        .index(outputIndex.trim()) // Use index from item
                        .id(docId)
                        .document(payloadMap) // Index the map representation
                );
                BulkOperation bulkOp = BulkOperation.of(op -> op.index(indexOp));

                // Add to shared BulkIngester
                this.ingester.add(bulkOp);
                addedCount++;

            } catch (Exception e) {
                // Log error for specific item preparation
                log.error("Failed to prepare ES index operation for item primaryId '{}', Doc ID '{}', Index '{}'. Payload: {}",
                          primaryId, docId, outputIndex, payload.toString().substring(0, Math.min(200, payload.toString().length())), e);
                // Decide: Continue chunk or fail step? For robustness, often log and continue.
                // To fail step: throw new RuntimeException("Failed to prepare ES operation for docId: " + docId, e);
            }
        }

        log.debug("Processed chunk for ES: Added {} operations to BulkIngester for index '{}', Skipped {} items.", addedCount, this.indexName, skippedCount);
        // BulkIngester flushes automatically based on its configuration (time/size/operations)
    }

    /**
     * Closes the BulkIngester when the bean is destroyed. Important for final flush.
     */
    @Override
    @PreDestroy // Ensure Spring calls this on context shutdown/bean destruction
    public void close() throws IOException {
        log.info("Closing BulkIngester for Factset writer (Index: '{}')...", this.indexName);
        try {
            this.ingester.close();
            log.info("BulkIngester for Factset writer closed successfully.");
        } catch (Exception e) {
            log.error("Error closing BulkIngester for Factset writer (Index: '{}')", this.indexName, e);
            // Log but don't necessarily throw from close unless absolutely critical
        }
    }




package com.example.requestpayload.batch.reader.common; // Or another suitable package

import com.example.requestpayload.service.FeedConfigService;
import org.springframework.batch.item.file.transform.DelimitedLineTokenizer;
import org.springframework.batch.item.file.transform.FieldSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component; // Make it a component for easy injection
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Parses a single line of CSV-like text into a Map<String, String>
  * based on column names fetched dynamically for a given feedFileType.
   */
   @Component // Register as a Spring bean
   public class CsvCommonParser {

       private static final Logger log = LoggerFactory.getLogger(CsvCommonParser.class);

           private final FeedConfigService feedConfigService;

               // Cache column names per feed type for efficiency within the job run
                   private final ConcurrentHashMap<String, String[]> columnCache = new ConcurrentHashMap<>();

                       @Autowired // Constructor injection
                           public CsvCommonParser(FeedConfigService feedConfigService) {
                                   this.feedConfigService = Objects.requireNonNull(feedConfigService);
                                       }

                                           /**
                                                * Parses a single line into a Map using dynamically fetched columns.
                                                     *
                                                          * @param line The line of text to parse.
                                                               * @param feedFileType The type of feed, used to look up columns.
                                                                    * @param delimiter The delimiter character (e.g., ";").
                                                                         * @return A Map<String, String> where keys are column names and values are data.
                                                                              * @throws Exception If parsing fails or columns cannot be fetched.
                                                                                   */
                                                                                       public Map<String, String> parseLine(String line, String feedFileType, String delimiter) throws Exception {
                                                                                               if (!StringUtils.hasText(line)) {
                                                                                                           log.trace("Skipping blank line.");
                                                                                                                       return Collections.emptyMap(); // Return empty map for blank lines
                                                                                                                               }

                                                                                                                                       // Get column names (use cache)
                                                                                                                                               String[] columnNames = columnCache.computeIfAbsent(feedFileType, key -> {
                                                                                                                                                           log.debug("Fetching column names for feed type: {}", key);
                                                                                                                                                                       List<String> cols = feedConfigService.getExpectedColumnNames(key);
                                                                                                                                                                                   if (cols == null || cols.isEmpty()) {
                                                                                                                                                                                                   log.error("No columns configured in DB for feed type: {}", key);
                                                                                                                                                                                                                   // Throw a specific exception or handle as needed
                                                                                                                                                                                                                                   throw new RuntimeException("No columns configured for feed type: " + key);
                                                                                                                                                                                                                                               }
                                                                                                                                                                                                                                                           return cols.toArray(new String[0]);
                                                                                                                                                                                                                                                                   });

                                                                                                                                                                                                                                                                           // Configure tokenizer on-the-fly for this line
                                                                                                                                                                                                                                                                                   DelimitedLineTokenizer tokenizer = new DelimitedLineTokenizer();
                                                                                                                                                                                                                                                                                           tokenizer.setDelimiter(delimiter);
                                                                                                                                                                                                                                                                                                   tokenizer.setNames(columnNames);
                                                                                                                                                                                                                                                                                                           tokenizer.setStrict(true); // Ensure token count matches column count

                                                                                                                                                                                                                                                                                                                   FieldSet fieldSet;
                                                                                                                                                                                                                                                                                                                           try {
                                                                                                                                                                                                                                                                                                                                       fieldSet = tokenizer.tokenize(line);
                                                                                                                                                                                                                                                                                                                                               } catch (Exception e) {
                                                                                                                                                                                                                                                                                                                                                           log.error("Failed to tokenize line for feed type '{}'. Line: [{}]. Error: {}", feedFileType, line, e.getMessage());
                                                                                                                                                                                                                                                                                                                                                                       throw e; // Re-throw to allow step-level fault tolerance
                                                                                                                                                                                                                                                                                                                                                                               }

                                                                                                                                                                                                                                                                                                                                                                                       // Convert FieldSet to Map
                                                                                                                                                                                                                                                                                                                                                                                               Map<String, String> dataMap = new HashMap<>();
                                                                                                                                                                                                                                                                                                                                                                                                       for (String name : fieldSet.getNames()) {
                                                                                                                                                                                                                                                                                                                                                                                                                   // Trim values during mapping
                                                                                                                                                                                                                                                                                                                                                                                                                               dataMap.put(name, fieldSet.readString(name).trim());
                                                                                                                                                                                                                                                                                                                                                                                                                                       }

                                                                                                                                                                                                                                                                                                                                                                                                                                               log.trace("Parsed line to map: {}", dataMap);
                                                                                                                                                                                                                                                                                                                                                                                                                                                       return dataMap;
                                                                                                                                                                                                                                                                                                                                                                                                                                                           }
                                                                                                                                                                                                                                                                                                                                                                                                                                                           }


               package com.example.requestpayload.batch.reader.factset;

               import com.example.requestpayload.batch.reader.common.CsvCommonParser; // Import the common parser
               import com.example.requestpayload.dto.factset.FactsetSecurityItem;
               import org.springframework.batch.item.ExecutionContext;
               import org.springframework.batch.item.ItemStreamException;
               import org.springframework.batch.item.support.AbstractItemCountingItemStreamItemReader; // Use helper base class
               import org.springframework.beans.factory.InitializingBean;
               import org.springframework.core.io.FileSystemResource;
               import org.springframework.core.io.Resource;
               import org.springframework.util.Assert;
               import org.slf4j.Logger;
               import org.slf4j.LoggerFactory;

               import java.io.BufferedReader;
               import java.io.IOException;
               import java.nio.charset.StandardCharsets;
               import java.nio.file.Files;
               import java.nio.file.Paths;
               import java.util.Map;
               import java.util.Objects;

               /**
                * ItemStreamReader for Factset files.
                 * Reads file line by line, uses CsvCommonParser to get a Map<String, String>,
                  * then maps the Map to a FactsetSecurityItem DTO applying specific logic
                   * like identifier precedence.
                    *
                     * NOTE: Bean must be @StepScope. Assumes semicolon delimiter for Factset.
                      */
                      public class FactsetClientRequestItemReader extends AbstractItemCountingItemStreamItemReader<FactsetSecurityItem>
                              implements InitializingBean {

                                  private static final Logger log = LoggerFactory.getLogger(FactsetClientRequestItemReader.class);

                                      // Dependencies injected via constructor/bean definition
                                          private final String feedFileType; // Needed to pass to parser
                                              private final String filePath;
                                                  private final CsvCommonParser commonCsvParser; // Inject the common parser

                                                      private BufferedReader bufferedReader;
                                                          private Resource resource;
                                                              private int headerLinesToSkip = 1;
                                                                  private String delimiter = ";"; // Specific to Factset

                                                                      // Keys expected in the Map returned by the parser (should match DB config)
                                                                          private static final String KEY_INTERNAL_ID = "INTERNAL_ID";
                                                                              private static final String KEY_SEDOL = "SEDOL";
                                                                                  private static final String KEY_ISIN = "ISIN";
                                                                                      private static final String KEY_CUSIP = "CUSIP";
                                                                                          private static final String KEY_FACTSET_ID = "FACTSET_ID";
                                                                                              private static final String KEY_INSTRUMENT_TYPE = "INSTRUMENT_TYPE";
                                                                                                  private static final String KEY_REQUEST_DATE = "REQUEST_DATE";
                                                                                                      private static final String KEY_OUTPUT_NAME = "OUTPUT_NAME";

                                                                                                          public FactsetClientRequestItemReader(String feedFileType, String filePath, CsvCommonParser commonCsvParser) {
                                                                                                                  this.feedFileType = Objects.requireNonNull(feedFileType, "feedFileType cannot be null");
                                                                                                                          this.filePath = Objects.requireNonNull(filePath, "filePath cannot be null");
                                                                                                                                  this.commonCsvParser = Objects.requireNonNull(commonCsvParser, "commonCsvParser cannot be null");
                                                                                                                                          // Set a name for context persistence using feedFileType for potential uniqueness if needed
                                                                                                                                                  this.setName(FactsetClientRequestItemReader.class.getSimpleName() + "_" + feedFileType);
                                                                                                                                                      }

                                                                                                                                                          @Override
                                                                                                                                                              protected FactsetSecurityItem doRead() throws Exception {
                                                                                                                                                                      String line = readLine();
                                                                                                                                                                              if (line == null) {
                                                                                                                                                                                          return null; // End of file
                                                                                                                                                                                                  }

                                                                                                                                                                                                          // Step 1: Use Common Parser to get Map
                                                                                                                                                                                                                  Map<String, String> dataMap = commonCsvParser.parseLine(line, this.feedFileType, this.delimiter);
                                                                                                                                                                                                                          if (dataMap == null || dataMap.isEmpty()) {
                                                                                                                                                                                                                                      log.warn("Common parser returned empty map for line: {}", line);
                                                                                                                                                                                                                                                  return null; // Skip this line
                                                                                                                                                                                                                                                          }

                                                                                                                                                                                                                                                                  // Step 2: Map the Map to FactsetSecurityItem DTO (Factset Specific Logic)
                                                                                                                                                                                                                                                                          return mapDataMapToFactsetDto(dataMap);
                                                                                                                                                                                                                                                                              }

                                                                                                                                                                                                                                                                                  /**
                                                                                                                                                                                                                                                                                       * Reads the next line using the underlying BufferedReader.
                                                                                                                                                                                                                                                                                            */
                                                                                                                                                                                                                                                                                                protected String readLine() throws IOException {
                                                                                                                                                                                                                                                                                                        if (bufferedReader == null) {
                                                                                                                                                                                                                                                                                                                    throw new ItemStreamException("Reader must be open before it can be read.");
                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                    return this.bufferedReader.readLine();
                                                                                                                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                                                                                                                            /**
                                                                                                                                                                                                                                                                                                                                                 * Maps the data from the parsed Map into the FactsetSecurityItem DTO.
                                                                                                                                                                                                                                                                                                                                                      * Contains Factset-specific logic like identifier precedence.
                                                                                                                                                                                                                                                                                                                                                           */
                                                                                                                                                                                                                                                                                                                                                               private FactsetSecurityItem mapDataMapToFactsetDto(Map<String, String> dataMap) {
                                                                                                                                                                                                                                                                                                                                                                       // --- Extract values using expected keys ---
                                                                                                                                                                                                                                                                                                                                                                               String sedol = dataMap.getOrDefault(KEY_SEDOL, "");
                                                                                                                                                                                                                                                                                                                                                                                       String isin = dataMap.getOrDefault(KEY_ISIN, "");
                                                                                                                                                                                                                                                                                                                                                                                               String cusip = dataMap.getOrDefault(KEY_CUSIP, "");
                                                                                                                                                                                                                                                                                                                                                                                                       String factsetId = dataMap.getOrDefault(KEY_FACTSET_ID, "");
                                                                                                                                                                                                                                                                                                                                                                                                               String instrumentType = dataMap.getOrDefault(KEY_INSTRUMENT_TYPE, "");
                                                                                                                                                                                                                                                                                                                                                                                                                       String internalId = dataMap.getOrDefault(KEY_INTERNAL_ID, "");
                                                                                                                                                                                                                                                                                                                                                                                                                               String requestDate = dataMap.getOrDefault(KEY_REQUEST_DATE, "");
                                                                                                                                                                                                                                                                                                                                                                                                                                       String outputName = dataMap.getOrDefault(KEY_OUTPUT_NAME, "");

                                                                                                                                                                                                                                                                                                                                                                                                                                               // --- Identifier Precedence Logic ---
                                                                                                                                                                                                                                                                                                                                                                                                                                                       String primaryId = null;
                                                                                                                                                                                                                                                                                                                                                                                                                                                               String idType = null;
                                                                                                                                                                                                                                                                                                                                                                                                                                                                       if (!sedol.isBlank()) { primaryId = sedol; idType = "SEDOL"; }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                               else if (!isin.isBlank()) { primaryId = isin; idType = "ISIN"; }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       else if (!cusip.isBlank()) { primaryId = cusip; idType = "CUSIP"; }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               else if (!factsetId.isBlank()) { primaryId = factsetId; idType = "FACTSET_ID"; }

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       if (primaryId == null) {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   log.error("No valid identifier found in data map for Internal ID: {}", internalId);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               throw new IllegalArgumentException("Cannot process item, no valid identifier found for Internal ID: " + internalId);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           // Or return null: // return null;
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   }

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           // --- Create DTO ---
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   return new FactsetSecurityItem(primaryId, idType, instrumentType, internalId, requestDate, outputName);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       }


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           @Override
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               protected void doOpen() throws Exception {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       Assert.state(this.filePath != null, "Input filePath must be set");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               this.resource = new FileSystemResource(this.filePath);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       Assert.state(this.resource.exists(), "Input resource must exist: " + this.resource);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               Assert.state(this.resource.isReadable(), "Input resource must be readable: " + this.resource);

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       log.info("Opening reader for resource: {}", this.resource);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               this.bufferedReader = Files.newBufferedReader(Paths.get(this.filePath), StandardCharsets.UTF_8); // Use appropriate charset

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       // Skip Header Lines
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               for (int i = 0; i < headerLinesToSkip; i++) {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           String headerLine = readLine(); // Use the class's readLine method
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       log.debug("Skipping header line {}: {}", i + 1, headerLine);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   if (headerLine == null) { // EOF check
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   log.warn("End of file reached while skipping header lines.");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   break;
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           // Increment internal count if necessary (AbstractItemCountingItemStreamItemReader handles this)
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       // super.update(new ExecutionContext()); // Or equivalent if needed
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        log.debug("Finished skipping header lines.");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            }


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                @Override
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    protected void doClose() throws Exception {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             log.info("Closing reader for resource: {}", this.resource);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      if (this.bufferedReader != null) {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   try { this.bufferedReader.close(); }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                finally { this.bufferedReader = null; }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             }

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @Override
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     public void afterPropertiesSet() throws Exception {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             // Validation of injected dependencies
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     Assert.notNull(filePath, "filePath is required");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             Assert.notNull(feedFileType, "feedFileType is required");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     Assert.notNull(commonCsvParser, "commonCsvParser is required");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         }

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             // Optional: Setters for configuration if needed
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 public void setHeaderLinesToSkip(int headerLinesToSkip) { this.headerLinesToSkip = headerLinesToSkip; }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     public void setDelimiter(String delimiter) { this.delimiter = delimiter; }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     }

 // In FactsetBatchConfig.java

 import com.example.requestpayload.batch.reader.factset.FactsetClientRequestItemReader; // Import the updated reader
 import com.example.requestpayload.batch.reader.common.CsvCommonParser; // Import the common parser
 import com.example.requestpayload.dto.factset.FactsetSecurityItem; // Reader output type
 import com.example.requestpayload.service.FeedConfigService; // Service needed by parser
 // ... other imports ...

 @Configuration
 public class FactsetBatchConfig {
     // ... Autowired dependencies (including FeedConfigService) ...
         @Autowired private FeedConfigService feedConfigService;

             // === Define the Common Parser Bean ===
                 @Bean
                     public CsvCommonParser csvCommonParser() {
                             // Inject dependencies needed by the parser (FeedConfigService)
                                     return new CsvCommonParser(feedConfigService);
                                         }

                                             // === Factset Reader Bean Definition (Uses Common Parser) ===
                                                 @Bean("factsetClientRequestItemReader")
                                                     @StepScope // ESSENTIAL for Job Parameters
                                                         public FactsetClientRequestItemReader factsetClientRequestItemReader(
                                                                     // Inject necessary Job Parameters
                                                                                 @Value("#{jobParameters['feedFileType']}") String feedFileType,
                                                                                             @Value("#{jobParameters['fullPathFileName']}") String filePath,
                                                                                                         // Inject the CsvCommonParser bean
                                                                                                                     CsvCommonParser commonCsvParser
                                                                                                                                 ) {
                                                                                                                                         // Instantiate the reader, passing dependencies
                                                                                                                                                 FactsetClientRequestItemReader reader = new FactsetClientRequestItemReader(feedFileType, filePath, commonCsvParser);
                                                                                                                                                         // reader.setDelimiter(";"); // Optional: set if not default or fetched from config
                                                                                                                                                                 // reader.setHeaderLinesToSkip(1); // Optional: set if not default
                                                                                                                                                                         return reader;
                                                                                                                                                                             }

                                                                                                                                                                                 // === Step Definition (Input type is FactsetSecurityItem) ===
                                                                                                                                                                                     @Bean("factsetFileLoadStep")
                                                                                                                                                                                         public Step factsetFileLoadStep(
                                                                                                                                                                                                     // ... JobRepository, TxManager ...
                                                                                                                                                                                                                 // Inject the specific reader bean
                                                                                                                                                                                                                             @Qualifier("factsetClientRequestItemReader") ItemReader<FactsetSecurityItem> reader,
                                                                                                                                                                                                                                         // Inject the specific processor bean
                                                                                                                                                                                                                                                     @Qualifier("factsetClientRequestItemProcessor") ItemProcessor<FactsetSecurityItem, FactsetProcessedSecurityItem> processor,
                                                                                                                                                                                                                                                                 // Inject the composite writer bean
                                                                                                                                                                                                                                                                             @Qualifier("factsetCompositeWriter") CompositeItemWriter<FactsetProcessedSecurityItem> writer,
                                                                                                                                                                                                                                                                                         // ... listeners, taskExecutor ...
                                                                                                                                                                                                                                                                                                     ) {
                                                                                                                                                                                                                                                                                                             return new StepBuilder("FACTSET-FILE-LOAD", jobRepository)
                                                                                                                                                                                                                                                                                                                             // Step processes specific DTOs
                                                                                                                                                                                                                                                                                                                                             .<FactsetSecurityItem, FactsetProcessedSecurityItem>chunk(100, transactionManager)
                                                                                                                                                                                                                                                                                                                                                             .reader(reader) // Use specific Factset reader bean
                                                                                                                                                                                                                                                                                                                                                                             .processor(processor)
                                                                                                                                                                                                                                                                                                                                                                                             .writer(writer)
                                                                                                                                                                                                                                                                                                                                                                                                             // ... listeners, taskExecutor ...
                                                                                                                                                                                                                                                                                                                                                                                                                             .build();
                                                                                                                                                                                                                                                                                                                                                                                                                                 }

                                                                                                                                                                                                                                                                                                                                                                                                                                     // ... other beans (Processor, Writers, Listeners, Job) ...
                                                                                                                                                                                                                                                                                                                                                                                                                                         // Processor bean definition should still take FactsetSecurityItem as input
                                                                                                                                                                                                                                                                                                                                                                                                                                              @Bean("factsetClientRequestItemProcessor")
                                                                                                                                                                                                                                                                                                                                                                                                                                                   @StepScope
                                                                                                                                                                                                                                                                                                                                                                                                                                                        public FactsetClientRequestItemProcessor factsetClientRequestItemProcessor(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                 // ... inject job params needed by processor ...
                                                                                                                                                                                                                                                                                                                                                                                                                                                                          @Value("#{jobParameters['clientRequestIdentifier']}") String reqId,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   @Value("#{jobParameters['skipCache']}") String skipCache,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            @Value("#{jobParameters['outputIndex']}") String outputIndex,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ProviderParamService providerParamService // Needs this service
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          ) {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   // Processor takes FactsetSecurityItem as input
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            return new FactsetClientRequestItemProcessor(reqId, Boolean.parseBoolean(skipCache), outputIndex, /* providerCacheIndex? */, providerParamService);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                







import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import org.springframework.core.io.Resource;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class CsvCommonParser {

    public <T> List<T> parse(
        Resource file,
        List<String> requiredHeaders,
        String delimiter,
        Class<T> targetType
    ) throws IOException, CsvValidationException {
        
        try (InputStream stream = file.getInputStream();
             CSVReader reader = new CSVReader(new InputStreamReader(stream))) {
            
            // Read and validate headers
            String[] csvHeaders = reader.readNext();
            validateHeaders(csvHeaders, requiredHeaders);
            
            // Parse rows
            List<T> items = new ArrayList<>();
            String[] row;
            while ((row = reader.readNext()) != null) {
                items.add(mapRowToItem(row, targetType));
            }
            return items;
        }
    }

    // Streaming version for large files
    public <T> Iterable<T> parseStreaming(
        Resource file,
        List<String> requiredHeaders,
        String delimiter,
        Class<T> targetType
    ) throws IOException, CsvValidationException {
        
        InputStream stream = file.getInputStream();
        CSVReader reader = new CSVReader(new InputStreamReader(stream));
        
        // Validate headers
        String[] csvHeaders = reader.readNext();
        validateHeaders(csvHeaders, requiredHeaders);
        
        return () -> new Iterator<T>() {
            String[] nextRow;

            @Override
            public boolean hasNext() {
                try {
                    nextRow = reader.readNext();
                    return nextRow != null;
                } catch (Exception e) {
                    closeReader();
                    return false;
                }
            }

            @Override
            public T next() {
                return mapRowToItem(nextRow, targetType);
            }

            private void closeReader() {
                try {
                    reader.close();
                    stream.close();
                } catch (IOException ignored) {}
            }
        };
    }

    // ------------------------------------
    // Helper Methods
    // ------------------------------------
    
    private void validateHeaders(String[] csvHeaders, List<String> requiredHeaders) {
        List<String> missing = requiredHeaders.stream()
            .filter(h -> !containsIgnoreCase(csvHeaders, h))
            .toList();
        
        if (!missing.isEmpty()) {
            throw new InvalidCsvHeaderException(
                "Missing required headers: " + missing
            );
        }
    }

    private boolean containsIgnoreCase(String[] array, String value) {
        for (String item : array) {
            if (item.trim().equalsIgnoreCase(value)) return true;
        }
        return false;
    }

    private <T> T mapRowToItem(String[] row, Class<T> targetType) {
        // Implementation depends on your mapping strategy:
        // - Use reflection
        // - Use a pre-defined mapper (like CsvParsingStrategy)
        // Example for FactsetSecurityItem:
        FactsetSecurityItem item = new FactsetSecurityItem();
        item.setInternalId(row[0]);
        item.setSedol(row[1]);
        // ... map all fields
        return (T) item;
    }
}



graph TD
    A[Client] -->|AMD CSV/Flat File| B(service-main)
    B --> C[Convert to JSON<br>Spring Batch]
    C -->|JSON Request| D(service-translator)
    D --> E[API Data Collector]
    E --> F{Batch by Threshold}
    F -->|Batch Process| G[Polling Channel]
    G --> H[Send to Provider]
    H --> I{Response?}
    I -->|Yes| J[Store in COS]
    I -->|No| K[Retry<br>Max 20x]
    K -->|Success| J
    K -->|Fail| L[Update Fail Status]
    J --> M[Kafka Notification]
    M --> B
    B --> N[Process Response<br>Spring Batch]
    N --> O[Client Response<br>Spring Batch]
    O --> P[Deliver to Client]
    L --> Q[Failure Notification]

        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data Ingestion Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #e0f7ff 0%, #f0f9ff 100%);
            color: #2c3e50;
            min-height: 100vh;
        }

        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: rgba(255, 255, 255, 0.25);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }

        .nav-tabs {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .nav-tab {
            padding: 10px 20px;
            background: rgba(255, 255, 255, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.5);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            color: #3498db;
            font-weight: 500;
        }

        .nav-tab.active {
            background: rgba(52, 152, 219, 0.2);
            color: #2c3e50;
            border: 1px solid rgba(52, 152, 219, 0.3);
        }

        .nav-tab:hover {
            background: rgba(255, 255, 255, 0.6);
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .summary-card h3 {
            color: #7f8c8d;
            font-size: 14px;
            margin-bottom: 10px;
        }

        .summary-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
        }

        .summary-card .change {
            font-size: 14px;
            margin-top: 5px;
        }

        .positive { color: #27ae60; }
        .negative { color: #e74c3c; }

        .charts-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-container {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .chart-container h3 {
            margin-bottom: 20px;
            color: #2c3e50;
        }

        .progress-section {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .progress-bar {
            width: 100%;
            height: 30px;
            background: rgba(236, 240, 241, 0.5);
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
            border: 1px solid rgba(255, 255, 255, 0.5);
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #3498db 0%, #2ecc71 100%);
            width: 65%;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            box-shadow: 0 0 10px rgba(46, 204, 113, 0.3);
        }

        .upload-section {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            text-align: center;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .upload-area {
            border: 2px dashed rgba(52, 152, 219, 0.5);
            border-radius: 16px;
            padding: 40px;
            margin: 20px 0;
            cursor: pointer;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.3);
        }

        .upload-area:hover {
            border-color: #3498db;
            background: rgba(236, 240, 241, 0.4);
            transform: translateY(-2px);
        }

        .folder-structure {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .folder {
            margin-left: 20px;
            margin-top: 10px;
        }

        .folder-item {
            padding: 8px;
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.3s ease;
        }

        .folder-item:hover {
            background: rgba(236, 240, 241, 0.4);
            transform: translateX(3px);
        }

        .folder-icon::before {
            content: "📁 ";
        }

        .file-icon::before {
            content: "📄 ";
        }

        .data-table {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }

        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .btn-primary {
            background: rgba(52, 152, 219, 0.8);
            color: white;
            box-shadow: 0 4px 10px rgba(52, 152, 219, 0.2);
        }

        .btn-primary:hover {
            background: rgba(41, 128, 185, 0.9);
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(41, 128, 185, 0.3);
        }

        .btn-success {
            background: rgba(46, 204, 113, 0.8);
            color: white;
            box-shadow: 0 4px 10px rgba(46, 204, 113, 0.2);
        }

        .btn-success:hover {
            background: rgba(39, 174, 96, 0.9);
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(39, 174, 96, 0.3);
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }

        .status-running {
            background-color: #3498db;
            color: white;
        }

        .status-completed {
            background-color: #27ae60;
            color: white;
        }

        .status-failed {
            background-color: #e74c3c;
            color: white;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }

        .modal-content {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(20px);
            margin: 5% auto;
            padding: 30px;
            border-radius: 16px;
            width: 80%;
            max-width: 600px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.5);
        }

        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }

        .close:hover {
            color: #000;
        }

        .config-wizard {
            display: grid;
            gap: 20px;
        }

        .wizard-step {
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.5);
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.3);
            backdrop-filter: blur(5px);
        }

        .form-group {
            margin-bottom: 15px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }

        .form-group input,
        .form-group select {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }

        .checkbox-group {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }

        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <h1>Data Ingestion Dashboard</h1>
            <p>Process and standardize vendor files with intelligent mapping</p>
            
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('dashboard')">Dashboard</button>
                <button class="nav-tab" onclick="showTab('upload')">Upload & Source</button>
                <button class="nav-tab" onclick="showTab('configure')">Configure</button>
                <button class="nav-tab" onclick="showTab('monitor')">Monitor</button>
                <button class="nav-tab" onclick="showTab('results')">Results</button>
            </div>
        </div>

        <!-- Dashboard Tab -->
        <div id="dashboard-tab" class="tab-content">
            <div class="summary-cards">
                <div class="summary-card">
                    <h3>Total Files Processed</h3>
                    <div class="value">1,247</div>
                    <div class="change positive">↑ 12% from last week</div>
                </div>
                <div class="summary-card">
                    <h3>Success Rate</h3>
                    <div class="value">94.2%</div>
                    <div class="change positive">↑ 2.1% from last week</div>
                </div>
                <div class="summary-card">
                    <h3>Average Processing Time</h3>
                    <div class="value">3.4 min</div>
                    <div class="change negative">↑ 0.3 min from last week</div>
                </div>
                <div class="summary-card">
                    <h3>Active Jobs</h3>
                    <div class="value">5</div>
                    <div class="change">Running now</div>
                </div>
            </div>

            <div class="charts-section">
                <div class="chart-container">
                    <h3>Data Quality KPIs</h3>
                    <canvas id="qualityChart" width="400" height="200"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Processing Status Distribution</h3>
                    <canvas id="statusChart" width="400" height="200"></canvas>
                </div>
            </div>

            <div class="progress-section">
                <h3>Current Job Progress</h3>
                <div class="progress-bar">
                    <div class="progress-fill">65%</div>
                </div>
                <p>Processing vendor file: <strong>equity_data_2024.csv</strong></p>
                <p>Status: <span class="status-badge status-running">Running</span> | Records processed: 45,678 / 70,234</p>
            </div>
        </div>

        <!-- Upload Tab -->
        <div id="upload-tab" class="tab-content" style="display: none;">
            <div class="upload-section">
                <h2>Upload Files</h2>
                <p>Drag and drop your files or click to browse</p>
                <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                    <p>📁 Select files to upload</p>
                    <p style="color: #7f8c8d; font-size: 14px; margin-top: 10px;">
                        Supported formats: CSV, Excel, JSON, XML, PDF, Email
                    </p>
                </div>
                <input type="file" id="fileInput" multiple style="display: none;" onchange="handleFileSelect(event)">
                
                <div style="margin-top: 20px;">
                    <h3>Or Connect to API</h3>
                    <button class="btn btn-primary">Configure API Source</button>
                </div>
            </div>

            <div class="folder-structure">
                <h3>Recent Files</h3>
                <div class="folder-item folder-icon">Vendor Data</div>
                <div class="folder" style="margin-left: 40px;">
                    <div class="folder-item file-icon">equity_data_2024.csv</div>
                    <div class="folder-item file-icon">bond_prices.xml</div>
                    <div class="folder-item folder-icon">Mapping Files</div>
                    <div class="folder" style="margin-left: 40px;">
                        <div class="folder-item file-icon">currency_mapping.csv</div>
                        <div class="folder-item file-icon">market_mapping.json</div>
                        <div class="folder-item file-icon">decimal_mapping.xlsx</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Configure Tab -->
        <div id="configure-tab" class="tab-content" style="display: none;">
            <div class="chart-container">
                <h2>Extraction Configuration Wizard</h2>
                <div class="config-wizard">
                    <div class="wizard-step">
                        <h3>Step 1: Schema Detection</h3>
                        <div class="form-group">
                            <label>Detection Mode:</label>
                            <select>
                                <option>Auto-detect schema</option>
                                <option>Use predefined schema</option>
                                <option>Manual configuration</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="wizard-step">
                        <h3>Step 2: Load Mapping Files</h3>
                        <button class="btn btn-primary">Browse Mapping Files</button>
                        <div style="margin-top: 10px;">
                            <p>✓ Currency mapping loaded</p>
                            <p>✓ Market mapping loaded</p>
                            <p>✓ Decimal mapping loaded</p>
                        </div>
                    </div>
                    
                    <div class="wizard-step">
                        <h3>Step 3: Select Required Fields</h3>
                        <div class="checkbox-group">
                            <div class="checkbox-item">
                                <input type="checkbox" checked> Security ID
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" checked> Price
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" checked> Currency
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox"> Market
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" checked> Timestamp
                            </div>
                        </div>
                    </div>
                    
                    <div class="wizard-step">
                        <h3>Step 4: Validation Rules</h3>
                        <div class="form-group">
                            <label>Price Range:</label>
                            <input type="text" placeholder="Min: 0, Max: 1000000">
                        </div>
                        <div class="form-group">
                            <label>Required Fields:</label>
                            <input type="text" placeholder="security_id, price, currency">
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" checked> Remove duplicates
                        </div>
                    </div>
                </div>
                <button class="btn btn-success" style="margin-top: 20px;">Save Configuration</button>
            </div>
        </div>

        <!-- Monitor Tab -->
        <div id="monitor-tab" class="tab-content" style="display: none;">
            <div class="chart-container">
                <h2>Job Monitoring</h2>
                <button class="btn btn-primary">Start New Job</button>
                <button class="btn btn-primary" style="margin-left: 10px;">Schedule Job</button>
                
                <div style="margin-top: 20px;">
                    <h3>Active Jobs</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Job ID</th>
                                <th>File Name</th>
                                <th>Status</th>
                                <th>Progress</th>
                                <th>Start Time</th>
                                <th>ETA</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>#J2024001</td>
                                <td>equity_data_2024.csv</td>
                                <td><span class="status-badge status-running">Running</span></td>
                                <td>65%</td>
                                <td>14:30:22</td>
                                <td>14:35:00</td>
                            </tr>
                            <tr>
                                <td>#J2024002</td>
                                <td>bond_prices.xml</td>
                                <td><span class="status-badge status-running">Running</span></td>
                                <td>23%</td>
                                <td>14:31:45</td>
                                <td>14:38:00</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <div style="margin-top: 20px;">
                    <h3>Recent Completed Jobs</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Job ID</th>
                                <th>File Name</th>
                                <th>Status</th>
                                <th>Records Processed</th>
                                <th>Duration</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>#J2024000</td>
                                <td>fx_rates.json</td>
                                <td><span class="status-badge status-completed">Completed</span></td>
                                <td>15,234</td>
                                <td>2m 15s</td>
                                <td><button class="btn btn-primary">View Results</button></td>
                            </tr>
                            <tr>
                                <td>#J2023999</td>
                                <td>market_data.pdf</td>
                                <td><span class="status-badge status-failed">Failed</span></td>
                                <td>0</td>
                                <td>30s</td>
                                <td><button class="btn btn-primary">View Error</button></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Results Tab -->
        <div id="results-tab" class="tab-content" style="display: none;">
            <div class="data-table">
                <h2>Processed Data Results</h2>
                <div style="margin-bottom: 20px;">
                    <input type="text" placeholder="Search..." style="padding: 8px; width: 300px;">
                    <button class="btn btn-primary" style="margin-left: 10px;">Filter</button>
                    <button class="btn btn-success" style="float: right;">Export to CSV</button>
                    <button class="btn btn-success" style="float: right; margin-right: 10px;">Export to Excel</button>
                    <button class="btn btn-success" style="float: right; margin-right: 10px;">Export to JSON</button>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Security ID</th>
                            <th>Security Name</th>
                            <th>Price</th>
                            <th>Currency</th>
                            <th>Market</th>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Quality Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>AAPL</td>
                            <td>Apple Inc.</td>
                            <td>182.52</td>
                            <td>USD</td>
                            <td>NASDAQ</td>
                            <td>2024-01-15 14:30:00</td>
                            <td>equity_data_2024.csv</td>
                            <td>100%</td>
                        </tr>
                        <tr>
                            <td>MSFT</td>
                            <td>Microsoft Corp.</td>
                            <td>423.08</td>
                            <td>USD</td>
                            <td>NASDAQ</td>
                            <td>2024-01-15 14:30:00</td>
                            <td>equity_data_2024.csv</td>
                            <td>100%</td>
                        </tr>
                        <tr>
                            <td>GOOGL</td>
                            <td>Alphabet Inc.</td>
                            <td>155.32</td>
                            <td>USD</td>
                            <td>NASDAQ</td>
                            <td>2024-01-15 14:30:00</td>
                            <td>equity_data_2024.csv</td>
                            <td>95%</td>
                        </tr>
                    </tbody>
                </table>
                
                <div style="margin-top: 20px; text-align: center;">
                    <button class="btn btn-primary">Previous</button>
                    <span style="margin: 0 20px;">Page 1 of 150</span>
                    <button class="btn btn-primary">Next</button>
                </div>
            </div>
            
            <div class="chart-container" style="margin-top: 20px;">
                <h3>Data Quality Metrics</h3>
                <p>Missing Fields: 2.3% | Validation Errors: 0.8% | Duplicate Records: 0.1%</p>
                <canvas id="qualityMetricsChart" width="400" height="150"></canvas>
            </div>
        </div>
    </div>

    <!-- Configuration Modal -->
    <div id="configModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h2>Configuration Details</h2>
            <p>Configuration saved successfully!</p>
        </div>
    </div>

    <script>
        function showTab(tabName) {
            // Hide all tabs
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.style.display = 'none');
            
            // Remove active class from all nav tabs
            const navTabs = document.querySelectorAll('.nav-tab');
            navTabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName + '-tab').style.display = 'block';
            
            // Add active class to clicked nav tab
            event.target.classList.add('active');
        }

        function handleFileSelect(event) {
            const files = event.target.files;
            alert(`Selected ${files.length} file(s) for upload`);
        }

        function closeModal() {
            document.getElementById('configModal').style.display = 'none';
        }

        // Simple chart drawing functions
        function drawBarChart(canvasId, data) {
            const canvas = document.getElementById(canvasId);
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;
            
            // Clear canvas
            ctx.clearRect(0, 0, width, height);
            
            // Draw bars
            const barWidth = width / (data.length * 2);
            const maxValue = Math.max(...data.map(d => d.value));
            
            data.forEach((item, index) => {
                const barHeight = (item.value / maxValue) * (height - 40);
                const x = index * barWidth * 2 + barWidth / 2;
                const y = height - barHeight - 20;
                
                // Draw bar
                ctx.fillStyle = '#3498db';
                ctx.fillRect(x, y, barWidth, barHeight);
                
                // Draw label
                ctx.fillStyle = '#2c3e50';
                ctx.font = '12px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(item.label, x + barWidth / 2, height - 5);
                
                // Draw value
                ctx.fillText(item.value + '%', x + barWidth / 2, y - 5);
            });
        }

        function drawPieChart(canvasId, data) {
            const canvas = document.getElementById(canvasId);
            const ctx = canvas.getContext('2d');
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = Math.min(centerX, centerY) - 20;
            
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            let currentAngle = -Math.PI / 2;
            const total = data.reduce((sum, item) => sum + item.value, 0);
            
            data.forEach((item, index) => {
                const sliceAngle = (item.value / total) * 2 * Math.PI;
                
                // Draw slice
                ctx.beginPath();
                ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
                ctx.lineTo(centerX, centerY);
                ctx.fillStyle = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12'][index % 4];
                ctx.fill();
                
                // Draw label
                const labelX = centerX + Math.cos(currentAngle + sliceAngle / 2) * (radius / 2);
                const labelY = centerY + Math.sin(currentAngle + sliceAngle / 2) * (radius / 2);
                
                ctx.fillStyle = '#2c3e50';
                ctx.font = 'bold 12px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(item.label, labelX, labelY);
                
                currentAngle += sliceAngle;
            });
        }

        // Initialize charts
        window.onload = function() {
            // Quality KPIs chart
            drawBarChart('qualityChart', [
                { label: 'Missing Fields', value: 2.3 },
                { label: 'Validation Errors', value: 0.8 },
                { label: 'Duplicates', value: 0.1 },
                { label: 'Format Issues', value: 1.5 }
            ]);
            
            // Status distribution chart
            drawPieChart('statusChart', [
                { label: 'Completed', value: 94.2 },
                { label: 'Failed', value: 3.5 },
                { label: 'Running', value: 2.3 }
            ]);
            
            // Quality metrics chart
            drawBarChart('qualityMetricsChart', [
                { label: 'Week 1', value: 95 },
                { label: 'Week 2', value: 96 },
                { label: 'Week 3', value: 94 },
                { label: 'Week 4', value: 97 }
            ]);
        };
    </script>
</body>
</html>
