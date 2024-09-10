// Import necessary crates and modules
use aes::Aes128; // Import AES-128 encryption algorithm
use block_modes::{BlockMode, Cbc}; // Import block mode traits and CBC mode
use block_modes::block_padding::Pkcs7; // Import PKCS7 padding for block ciphers
use pbkdf2::pbkdf2; // Import PBKDF2 key derivation function
use sha1::Sha1; // Import SHA-1 hashing algorithm
use hex::{encode, decode}; // Import hex encoding and decoding utilities
use serde_json::Value; // Import Serde for JSON handling
use std::fs::File; // Import File for file handling
use std::io::Read; // Import Read trait for reading files
use std::env; // Import env module for environment variable access
use keyring::Entry; // Import keyring for cross-platform secure storage
use hmac::Hmac; // Import HMAC for message authentication
use rand::Rng; // Import random number generation

/// Type alias for AES-128 CBC mode with PKCS7 padding.
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Constants for encryption and key derivation
const SALT: &[u8] = b"saltysalt"; // Salt used for PBKDF2 key derivation
const ITERATIONS: u32 = 1003; // Number of iterations for PBKDF2
const KEY_LENGTH: usize = 16; // Length of the derived AES key
const ENCRYPTION_VERSION_PREFIX: &str = "v10"; // Prefix indicating encryption version

// References:
// - https://github.com/electron/electron/blob/41b8fdca5c53a41eabdad9a6a75b45bda4a6f37b/shell/browser/api/electron_api_safe_storage.cc
// - https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_mac.mm
// - https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_win.cc
// - https://github.dev/electron/electron/blob/41b8fdca5c53a41eabdad9a6a75b45bda4a6f37b/patches/chromium/mas_avoid_private_macos_api_usage.patch.patch

/// A struct to encapsulate encryption and decryption logic.
struct OSCrypt {
    encrypted_key: String, // The encrypted key loaded from the configuration file
    aes_key: [u8; KEY_LENGTH], // The derived AES key used for encryption/decryption
}

impl OSCrypt {
    /// Constructs a new `OSCrypt` instance.
    ///
    /// # Arguments
    ///
    /// * `service_name` - A string slice that holds the name of the service.
    /// * `account_name` - A string slice that holds the account name.
    /// * `config_path` - An optional string slice that specifies the path to the configuration file.
    ///
    /// # Returns
    ///
    /// A Result containing either a new `OSCrypt` instance or an error.
    fn new(service_name: &str, account_name: &str, config_path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let encrypted_key = Self::load_encrypted_key(config_path)?; // Load encrypted key
        let secure_password = Self::get_secure_storage_password(service_name, account_name)?; // Retrieve password from secure storage
        let aes_key = Self::derive_key(&secure_password); // Derive AES key from the password
        Ok(Self { encrypted_key, aes_key }) // Return a new OSCrypt instance
    }

    /// Loads the encrypted key from a specified path or default path.
    ///
    /// # Arguments
    ///
    /// * `config_path` - An optional string slice that specifies the path to the configuration file.
    ///
    /// # Returns
    ///
    /// A Result containing either the encrypted key as a String or an error.
    fn load_encrypted_key(config_path: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
        let default_path; // Declare the variable to hold the default path
        let path = if let Some(cp) = config_path {
            cp // Use the specified config path if provided
        } else {
            default_path = Self::get_default_config_path()?; // Assign the default path to a variable
            &default_path // Borrow the default path
        };
        println!("Using config path: {}", path); // Print config path being used
        Self::load_config(path) // Load the encrypted key from the config file
    }

    /// Retrieves the password from the secure storage for the given service and account name.
    ///
    /// # Arguments
    ///
    /// * `service_name` - A string slice that holds the name of the service.
    /// * `account_name` - A string slice that holds the account name.
    ///
    /// # Returns
    ///
    /// A Result containing either the password as a String or an error.
    fn get_secure_storage_password(service_name: &str, account_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let entry = Entry::new(service_name, account_name); // Create a new keyring entry
        entry.get_password().map_err(|e| e.into()) // Retrieve password from secure storage
    }

    /// Derives an AES key from a password using PBKDF2 with SHA1.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that represents the password.
    ///
    /// # Returns
    ///
    /// A derived AES key as a byte array.
    fn derive_key(password: &str) -> [u8; KEY_LENGTH] {
        let mut key = [0u8; KEY_LENGTH]; // Initialize key buffer
        pbkdf2::<Hmac<Sha1>>(password.as_bytes(), SALT, ITERATIONS, &mut key); // Perform PBKDF2 key derivation
        key // Return the derived key
    }

    /// Loads configuration from a specified file path.
    ///
    /// # Arguments
    ///
    /// * `path` - A string slice that holds the path to the configuration file.
    ///
    /// # Returns
    ///
    /// A Result containing either the encrypted key as a String or an error.
    fn load_config(path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?; // Open the config file
        let mut contents = String::new(); // Create a string to hold file contents
        file.read_to_string(&mut contents)?; // Read file into string
        let v: Value = serde_json::from_str(&contents)?; // Parse JSON from string
        v["encryptedKey"].as_str().map(|s| s.to_string()).ok_or_else(|| "Missing encryptedKey".into()) // Extract encrypted key
    }

    /// Gets the default configuration path for the config file on macOS.
    ///
    /// # Returns
    ///
    /// A Result containing either the default config path as a String or an error.
    fn get_default_config_path() -> Result<String, Box<dyn std::error::Error>> {
        let home = env::var("HOME")?; // Get the home directory path
        Ok(format!("{}/Library/Application Support/Signal/config.json", home)) // Construct path for macOS
    }

    /// Encrypts a plaintext string using the derived AES key.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - A string slice that represents the plaintext to be encrypted.
    ///
    /// # Returns
    ///
    /// A Result containing either the encrypted string in hex format or an error.
    fn encrypt_string(&self, plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
        let iv = Self::generate_iv(); // Generate a random IV
        let cipher = Aes128Cbc::new_from_slices(&self.aes_key, &iv)?; // Create AES-CBC cipher with key and IV
        let mut result = ENCRYPTION_VERSION_PREFIX.as_bytes().to_vec(); // Start result with version prefix
        result.extend_from_slice(&iv); // Append IV to result
        result.extend_from_slice(&cipher.encrypt_vec(plaintext.as_bytes())); // Encrypt the plaintext and append ciphertext
        Ok(encode(result)) // Return the hex-encoded result
    }

    /// Decrypts a hex-encoded encrypted string using the derived AES key.
    ///
    /// # Arguments
    ///
    /// * `encrypted_hex` - A string slice that represents the encrypted data in hex format.
    ///
    /// # Returns
    ///
    /// A Result containing either the decrypted string or an error.
    fn decrypt_string(&self, encrypted_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
        let encrypted_data = decode(encrypted_hex)?; // Decode the hex string
        if !encrypted_data.starts_with(ENCRYPTION_VERSION_PREFIX.as_bytes()) {
            return Err("Invalid encryption version prefix".into()); // Validate encryption version prefix
        }

        let iv_end = ENCRYPTION_VERSION_PREFIX.len() + KEY_LENGTH; // Calculate end of IV in data
        let iv = &encrypted_data[ENCRYPTION_VERSION_PREFIX.len()..iv_end]; // Extract IV
        let encrypted_text = &encrypted_data[iv_end..]; // Extract encrypted text

        let cipher = Aes128Cbc::new_from_slices(&self.aes_key, iv)?; // Create AES-CBC cipher with extracted IV
        let decrypted = cipher.decrypt_vec(encrypted_text)?; // Decrypt the text
        String::from_utf8(decrypted).map_err(|e| e.into()) // Convert decrypted bytes to a UTF-8 string
    }

    /// Generates a random initialization vector (IV) for encryption.
    ///
    /// # Returns
    ///
    /// A random IV as a byte array.
    fn generate_iv() -> [u8; KEY_LENGTH] {
        let mut iv = [0u8; KEY_LENGTH]; // Initialize IV buffer
        rand::thread_rng().fill(&mut iv); // Fill IV with random bytes
        iv // Return the generated IV
    }
}

/// Prints the version information of the tool.
fn print_version() {
    println!("SignalDecryption version 1.0.0 (macOS)");
    println!("Compiled with Rust");
}

/// Prints help information for using the tool.
fn print_help() {
    println!("Usage: SignalDecryption [options]");
    println!("Options:");
    println!("  -h, --help         Show this help message");
    println!("  -c, --config PATH  Specify the path to the config.json file");
    println!("  -k, --key KEY      Provide an encrypted key directly");
    println!("  -p, --print-key    Print the secure storage key (use with caution)");
    println!("  --version          Show the tool version");
}

/// Main function to handle command-line arguments and execute encryption/decryption logic.
///
/// # Returns
///
/// A Result indicating success or failure.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect(); // Collect command-line arguments
    let mut config_path = None; // Optional path to config file
    let mut encrypted_key = None; // Optional encrypted key input
    let mut print_secure_key = false; // Flag to control printing of secure key

    // Parse command-line arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help(); // Print help message
                return Ok(());
            }
            "--version" => {
                print_version(); // Print version information
                return Ok(());
            }
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    config_path = Some(args[i + 1].clone()); // Set config path
                    i += 1; // Skip to next argument
                } else {
                    return Err("Option '-c' requires an argument.".into()); // Error if no argument is provided
                }
            }
            "-k" | "--key" => {
                if i + 1 < args.len() {
                    encrypted_key = Some(args[i + 1].clone()); // Set encrypted key
                    i += 1; // Skip to next argument
                } else {
                    return Err("Option '-k' requires an argument.".into()); // Error if no argument is provided
                }
            }
            "-p" | "--print-key" => {
                print_secure_key = true; // Enable printing of secure key
            }
            _ => return Err(format!("Unknown option: {}", args[i]).into()), // Error for unknown options
        }
        i += 1;
    }

    // Retrieve and optionally print the secure storage password
    let secure_password = match OSCrypt::get_secure_storage_password("Signal Safe Storage", "Signal Key") {
        Ok(password) => {
            if print_secure_key {
                println!("Secure key retrieved: {}", password);
            }
            password
        },
        Err(e) => {
            println!("Failed to retrieve secure key: {}", e);
            return Err(e.into());
        }
    };

    // Initialize OSCrypt based on provided options
    let os_crypt = if let Some(key) = encrypted_key {
        println!("Using directly provided encrypted key");
        let aes_key = OSCrypt::derive_key(&secure_password);
        OSCrypt {
            encrypted_key: key,
            aes_key,
        }
    } else {
        OSCrypt::new("Signal Safe Storage", "Signal Key", config_path.as_deref())?
    };

    println!("Encrypted key: {}", os_crypt.encrypted_key); // Print the encrypted key
    let decrypted = os_crypt.decrypt_string(&os_crypt.encrypted_key)?; // Decrypt the key
    println!("Decrypted key: {}", decrypted); // Print the decrypted key

    Ok(())
}