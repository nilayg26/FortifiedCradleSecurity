import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class FortifiedCradleSecurity {

    // =========================================================================
    // Data Structures for System Components
    // =========================================================================

    /**
     * Represents the global parameters of the system, established once during setup.
     */
    private static class GlobalParameters {
        private final String globalId;

        public GlobalParameters(String id) {
            this.globalId = id;
        }

        public String getId() {
            return this.globalId;
        }
    }

    /**
     * Holds the public and private keys for a specific attribute authority.
     */
    private static class AuthorityKeys {
        private final String authorityId;
        private final String publicKey;
        private final String privateKey;

        public AuthorityKeys(String id, String pubKey, String privKey) {
            this.authorityId = id;
            this.publicKey = pubKey;
            this.privateKey = privKey;
        }

        public String getPublicKey() {
            return this.publicKey;
        }
    }

    /**
     * Stores the secret keys for a user, mapped by the attributes they possess.
     */
    private static class UserSecretKey {
        private final String userId;
        private final Map<String, String> attributeKeys;

        public UserSecretKey(String id) {
            this.userId = id;
            this.attributeKeys = new HashMap<>();
        }

        public void addAttributeKey(String attribute, String key) {
            this.attributeKeys.put(attribute, key);
        }

        public Map<String, String> getAttributeKeys() {
            return this.attributeKeys;
        }

        public Set<String> getAttributes() {
            return this.attributeKeys.keySet();
        }
    }

    // =========================================================================
    // Core Cryptographic Functions
    // =========================================================================

    /**
     * Initializes the entire system with a global identifier.
     */
    public static GlobalParameters globalSetup(String id) {
        System.out.println("SYSTEM: Global Setup Initialized with ID: " + id);
        return new GlobalParameters(id);
    }

    /**
     * Sets up an attribute authority by generating its public and private keys.
     */
    public static AuthorityKeys authoritySetup(String authorityId, GlobalParameters gp) {
        System.out.println("AUTHORITY(" + authorityId + "): Setting up with Global ID: " + gp.getId());
        String privateKey = "PRIV_KEY_" + authorityId + "_" + sha256(gp.getId() + authorityId);
        String publicKey = "PUB_KEY_" + authorityId + "_" + sha256(privateKey);
        return new AuthorityKeys(authorityId, publicKey, privateKey);
    }

    /**
     * Generates a secret key for a user based on their attributes, issued by authorities.
     */
    public static UserSecretKey keyGeneration(String userId, String[] attributes, AuthorityKeys... authorities) {
        System.out.println("USER(" + userId + "): Requesting keys for attributes: " + Arrays.toString(attributes));
        UserSecretKey userKey = new UserSecretKey(userId);
        for (String attribute : attributes) {
            for (AuthorityKeys authority : authorities) {
                // In a real system, each authority would only issue keys for attributes it manages.
                String key = "USER_KEY_" + sha256(userId + attribute + authority.privateKey);
                userKey.addAttributeKey(attribute, key);
                 System.out.println("  - Generated key for attribute '" + attribute + "' from Authority '" + authority.authorityId + "'");
            }
        }
        return userKey;
    }

    /**
     * Encrypts a message under a given access policy.
     */
    public static String encrypt(String plaintext, String policy, GlobalParameters gp, AuthorityKeys... authorities) {
        System.out.println("ENCRYPTION: Encrypting data with policy: \"" + policy + "\"");
        String combinedPublicKeys = Arrays.stream(authorities)
                                          .map(AuthorityKeys::getPublicKey)
                                          .collect(Collectors.joining());
        String secret = sha256(plaintext + policy + combinedPublicKeys);
        String ciphertext = "ENCRYPTED[" + plaintext + "]_WITH_SECRET_[" + secret + "]_POLICY_[" + policy + "]";
        System.out.println("  - Generated Ciphertext: " + ciphertext);
        return ciphertext;
    }
    
    // =========================================================================
    // Outsourced Decryption and Transformation Functions
    // =========================================================================

    /**
     * Generates a transformation key for the proxy if the user's attributes satisfy the policy.
     */
    public static String transformationKeyGen(UserSecretKey userKey, String policy) {
        System.out.println("PROXY: Generating Transformation Key for user " + userKey.userId + " and policy \"" + policy + "\"");
        if (checkPolicy(policy, userKey.getAttributes())) {
             String combinedAttrKeys = userKey.getAttributeKeys().values().stream().collect(Collectors.joining());
             String transformationKey = "TRANS_KEY_" + sha256(combinedAttrKeys + policy);
             System.out.println("  - Policy satisfied. Transformation key generated.");
             return transformationKey;
        } else {
             System.out.println("  - Policy NOT satisfied. Cannot generate transformation key.");
             return null;
        }
    }
    
    /**
     * The proxy uses the transformation key to partially decrypt the ciphertext.
     */
    public static String outsourcedDecryption(String ciphertext, String transformationKey) {
        System.out.println("PROXY: Performing outsourced decryption.");
        if (transformationKey == null) {
            System.out.println("  - Failed. No transformation key provided.");
            return "OUTSOURCED_DECRYPTION_FAILED";
        }
        
        String[] parts = ciphertext.split("_WITH_SECRET_");
        String encryptedPart = parts[0];
        String secretAndPolicyPart = parts[1];
        
        String secret = secretAndPolicyPart.substring(1, secretAndPolicyPart.indexOf("]_POLICY_"));
        
        String partialCiphertext = "PARTIALLY_DECRYPTED[" + encryptedPart + "]_WITH_SECRET_[" + sha256(secret + transformationKey) + "]";
        System.out.println("  - Partial decryption complete.");
        return partialCiphertext;
    }
    
    /**
     * The end-user performs the final, lightweight decryption step to recover the message.
     */
    public static String decrypt(String partialCiphertext, UserSecretKey userKey, String policy) {
        System.out.println("USER(" + userKey.userId + "): Performing final decryption.");
        if (partialCiphertext.equals("OUTSOURCED_DECRYPTION_FAILED")) {
            System.out.println("  - Final decryption failed because outsourced decryption failed.");
            return null;
        }

        String innerContent = partialCiphertext.substring("PARTIALLY_DECRYPTED[".length(), partialCiphertext.length() - 1);
        String[] parts = innerContent.split("\\]_WITH_SECRET_\\[");

        if (parts.length != 2) {
             System.out.println("  - Decryption failed: Malformed partial ciphertext.");
             return null;
        }
        
        String encryptedPart = parts[0];
        // The hashedSecret and subsequent logic here is simplified for demonstration.
        // A full implementation would recompute the expected value to verify integrity.
        String hashedSecret = parts[1];

        // This part simulates the user using their keys to remove the final layer of encryption.
        String finalMessage = encryptedPart.substring("ENCRYPTED[".length());
        
        System.out.println("  - Decryption successful. Recovered message.");
        return finalMessage;
    }

    // =========================================================================
    // Utility and Helper Functions
    // =========================================================================

    /**
     * A helper function to compute the SHA-256 hash of a string (truncated for simplicity).
     */
    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().substring(0, 10);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * A simple policy checker to see if a user's attributes satisfy the policy string.
     * Supports AND and OR operations.
     */
    private static boolean checkPolicy(String policy, Set<String> attributes) {
        policy = policy.replaceAll("[()']", "");
        String[] orClauses = policy.split(" OR ");

        for (String orClause : orClauses) {
            String[] requiredAttributes = orClause.split(" AND ");
            boolean clauseSatisfied = true;
            for (String reqAttr : requiredAttributes) {
                if (!attributes.contains(reqAttr.trim())) {
                    clauseSatisfied = false;
                    break;
                }
            }
            if (clauseSatisfied) {
                return true; // If any OR clause is met, the policy is satisfied.
            }
        }
        return false; // If no OR clauses were met.
    }

    // =========================================================================
    // Main Method for Demonstration
    // =========================================================================

    public static void main(String[] args) {
        // 1. System and Authority Setup
        System.out.println("--- SYSTEM INITIALIZATION ---");
        GlobalParameters gp = globalSetup("FortifiedCradle_GP_v1");
        AuthorityKeys aa1 = authoritySetup("AA1", gp);
        AuthorityKeys aa2 = authoritySetup("AA2", gp);

        // 2. User Creation and Key Generation
        System.out.println("\n--- USER AND KEY GENERATION ---");
        String[] doctorAttributes = {"Doctor", "Cardiologist", "On-Call"};
        UserSecretKey doctorKey = keyGeneration("DrAlice", doctorAttributes, aa1, aa2);

        String[] parentAttributes = {"Parent", "PatientID:123"};
        UserSecretKey parentKey = keyGeneration("ParentBob", parentAttributes, aa1, aa2);

        // 3. Data Encryption with an Access Policy
        System.out.println("\n--- DATA ENCRYPTION ---");
        String healthData = "HeartRate: 120, SpO2: 98%";
        String policy = "('Parent' AND 'PatientID:123') OR ('Doctor' AND 'On-Call')";
        String ciphertext = encrypt(healthData, policy, gp, aa1, aa2);

        // 4. Decryption Scenario 1: A parent with correct attributes attempts decryption.
        System.out.println("\n--- DECRYPTION ATTEMPT 1: PARENT (Should Succeed) ---");
        String tkParent = transformationKeyGen(parentKey, policy);
        String partialCiphertextParent = outsourcedDecryption(ciphertext, tkParent);
        String decryptedMessageParent = decrypt(partialCiphertextParent, parentKey, policy);
        System.out.println("  => FINAL RECOVERED MESSAGE (Parent): " + decryptedMessageParent);
        
        // 5. Decryption Scenario 2: A doctor with correct attributes attempts decryption.
        System.out.println("\n--- DECRYPTION ATTEMPT 2: DOCTOR (Should Succeed) ---");
        String tkDoctor = transformationKeyGen(doctorKey, policy);
        String partialCiphertextDoctor = outsourcedDecryption(ciphertext, tkDoctor);
        String decryptedMessageDoctor = decrypt(partialCiphertextDoctor, doctorKey, policy);
        System.out.println("  => FINAL RECOVERED MESSAGE (Doctor): " + decryptedMessageDoctor);

        // 6. Decryption Scenario 3: A researcher with incorrect attributes fails decryption.
        System.out.println("\n--- DECRYPTION ATTEMPT 3: FAILED CASE (Researcher) ---");
        String[] researcherAttributes = {"Researcher"};
        UserSecretKey researcherKey = keyGeneration("ResearcherCharlie", researcherAttributes, aa1, aa2);
        String tkResearcher = transformationKeyGen(researcherKey, policy);
        String partialCiphertextResearcher = outsourcedDecryption(ciphertext, tkResearcher);
        String decryptedMessageResearcher = decrypt(partialCiphertextResearcher, researcherKey, policy);
        System.out.println("  => FINAL RECOVERED MESSAGE (Researcher): " + decryptedMessageResearcher);
    }
}