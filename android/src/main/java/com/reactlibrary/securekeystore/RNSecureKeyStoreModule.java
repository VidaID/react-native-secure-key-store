/**
 * React Native Secure Key Store
 * Store keys securely in Android Keystore
 * Ref: cordova-plugin-secure-key-store
 */

package com.reactlibrary.securekeystore;

import android.content.Context;
import android.os.Build;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyPermanentlyInvalidatedException;

// todo: when api level 28 is more widespread use BiometricPrompt instead
import moe.feng.support.biometricprompt.BiometricPromptCompat;
import moe.feng.support.biometricprompt.BiometricPromptCompat.IAuthenticationCallback

import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import android.support.annotation.Nullable;
import com.facebook.react.bridge.ReadableMap;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class RNSecureKeyStoreModule extends ReactContextBaseJavaModule, IAuthenticationCallback {

  private final ReactApplicationContext reactContext;

  private CancellationSignal bioCancel;
  private Promise bioPm;
  private byte[] bioCipherBytes;
  private BiometricPromptCompat bioPrompt;

  public RNSecureKeyStoreModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
    Cipher cipher = result.getCryptoObject().getCipher()
    byte[] decrypted = decryptCipherText(cipher, bioCipherTextBytes);
    String base64 = Base64.encodeToString(decrypted, Base64.DEFAULT);
    bioPromise.resolve(base64);
  }

  @Override
  public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
      // existing display behavior is fine
  }

  @Override
  public void onAuthenticationError(int errorCode, CharSequence errString) {
    this.bioCipherBytes = null;
    this.bioCancel.cancel()
    bioPromise.reject(errString);
  }

  @Override
  public void onAuthenticationFailed() {
    this.bioCipherBytes = null;
    this.bioCancel.cancel()
    bioPromise.reject("Authentication failed");
  }

  @Override
  public String getName() {
    return "RNSecureKeyStore";
  }

  @ReactMethod
  public void set(String alias, String input, @Nullable ReadableMap options, Promise promise) {
    try {
      setCipherText(alias, input, options);
      promise.resolve("stored ciphertext in app storage");
    } catch (Exception e) {
      e.printStackTrace();
      Log.e(Constants.TAG, "Exception: " + e.getMessage());
      promise.reject("{\"code\":9,\"api-level\":" + Build.VERSION.SDK_INT + ",\"message\":" + e.getMessage() + "}");
    }
  }

  @ReactMethod
  public void decrypt(String alias, String b64input, @Nullable ReadableMap options, Promise promise) {
    try {
      byte[] data = Base64.decode(b64input, Base64.DEFAULT);

      // todo: decide if needs fingerprint first, then call this function
      decryptRsaToPromise(alias, data, promise);

      //byte[] decrypted = decryptRsaCipherText(getPrivateKey(alias), data);
      //String base64 = Base64.encodeToString(decrypted, Base64.DEFAULT);
      //promise.resolve(base64);
    } catch (Exception e) {
      e.printStackTrace();
      Log.e(Constants.TAG, "Exception: " + e.getMessage());
      promise.reject("{\"code\":9,\"api-level\":" + Build.VERSION.SDK_INT + ",\"message\":" + e.getMessage() + "}");
    }
  }

  @ReactMethod
  public void getPublicKey(String alias, String b64input, @Nullable ReadableMap options, Promise promise) {
    try {
      PublicKey publicKey = getOrCreatePublicKey(alias, options);
      byte[] pubk = publicKey.getEncoded();
      String base64 = Base64.encodeToString(pubk, Base64.DEFAULT);
      promise.resolve(base64);
    } catch (Exception e) {
      e.printStackTrace();
      Log.e(Constants.TAG, "Exception: " + e.getMessage());
      promise.reject("{\"code\":9,\"api-level\":" + Build.VERSION.SDK_INT + ",\"message\":" + e.getMessage() + "}");
    }
  }

  private PublicKey getOrCreatePublicKey(String alias, @Nullable ReadableMap options) throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(getKeyStore());
    keyStore.load(null);

    if (!keyStore.containsAlias(alias) || keyStore.getCertificate(alias) == null) {
      Log.i(Constants.TAG, "no existing asymmetric keys for alias");

      // todo: support ECIES whenever android gets around tuit
      // todo: make options affect how the key is created
      KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
          .setIsStrongBoxBacked(true)
          .setUserConfirmationRequired(true)
          .setUserAuthenticationRequired(true)
          // todo: detect max available in the hardware security module
          .setKeySize(2048)
          .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
          // todo: should be an option, not hardcoded
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
          .build();
      
      KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, getKeyStore());
      generator.initialize(spec);
      generator.generateKeyPair();

      Log.i(Constants.TAG, "created new asymmetric keys for alias");
      keyStore.load(null);
    }

    return keyStore.getKey(alias, null).getPublicKey();
  }

  private byte[] encryptRsaPlainText(PublicKey publicKey, byte[] plainTextBytes) throws GeneralSecurityException, IOException {
    Cipher cipher = Cipher.getInstance(Constants.RSA_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return encryptCipherText(cipher, plainTextBytes);
  }

  private byte[] encryptAesPlainText(SecretKey secretKey, String plainText) throws GeneralSecurityException, IOException {
    Cipher cipher = Cipher.getInstance(Constants.AES_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return encryptCipherText(cipher, plainText);
  }

  private byte[] encryptCipherText(Cipher cipher, String plainText) throws GeneralSecurityException, IOException {
    return encryptCipherText(cipher, plainText.getBytes("UTF-8"));
  }

  private byte[] encryptCipherText(Cipher cipher, byte[] plainTextBytes) throws GeneralSecurityException, IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
    cipherOutputStream.write(plainTextBytes);
    cipherOutputStream.close();
    return outputStream.toByteArray();
  }

  private SecretKey getOrCreateSecretKey(String alias, @Nullable ReadableMap options) throws GeneralSecurityException, IOException {
    try {
      return getSymmetricKey(alias);
    } catch (FileNotFoundException fnfe) {
      Log.i(Constants.TAG, "no existing symmetric key for alias");

      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      //32bytes / 256bits AES key
      keyGenerator.init(256);
      SecretKey secretKey = keyGenerator.generateKey();
      PublicKey publicKey = getOrCreatePublicKey(alias, options);
      Storage.writeValues(getContext(), Constants.SKS_KEY_FILENAME + alias,
          encryptRsaPlainText(publicKey, secretKey.getEncoded()));

      Log.i(Constants.TAG, "created new symmetric keys for alias");
      return secretKey;
    }
  }

  private void setCipherText(String alias, String input, @Nullable ReadableMap options) throws GeneralSecurityException, IOException {
    Storage.writeValues(getContext(), Constants.SKS_DATA_FILENAME + alias,
        encryptAesPlainText(getOrCreateSecretKey(alias, options), input));
  }

  @ReactMethod
  public void get(String alias, Promise promise) {
    try {
      promise.resolve(getPlainText(alias));
    } catch (FileNotFoundException fnfe) {
      fnfe.printStackTrace();
      promise.reject("404", "{\"code\":404,\"api-level\":" + Build.VERSION.SDK_INT + ",\"message\":" + fnfe.getMessage() + "}", fnfe);
    } catch (Exception e) {
      e.printStackTrace();
      Log.e(Constants.TAG, "Exception: " + e.getMessage());
      promise.reject("{\"code\":1,\"api-level\":" + Build.VERSION.SDK_INT + ",\"message\":" + e.getMessage() + "}");
    }
  }

  private PrivateKey getPrivateKey(String alias) throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(getKeyStore());
    keyStore.load(null);
    return (PrivateKey) keyStore.getKey(alias, null);
  }

  void decryptRsaToPromise(PrivateKey privateKey, byte[] cipherTextBytes, Promise pm) throws GeneralSecurityException, IOException {
      if (bioCancel != null) {
          bioCancel.cancel();
      }
      bioCancel = new CancellationSignal()
      bioPrompt = new BiometricPromptCompat.Builder(bioContext)
                        .setTitle("Authentication required")
                        .setSubtitle("Please use fingerprint reader to unlock")
                        .build();
      bioPm = pm;
      bioPrompt.authenticate(bioCancel, this);
  }

  private byte[] decryptRsaCipherText(PrivateKey privateKey, byte[] cipherTextBytes) throws GeneralSecurityException, IOException {
    Cipher cipher = Cipher.getInstance(Constants.RSA_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return decryptCipherText(cipher, cipherTextBytes);
  }

  private byte[] decryptAesCipherText(SecretKey secretKey, byte[] cipherTextBytes) throws GeneralSecurityException, IOException {
    Cipher cipher = Cipher.getInstance(Constants.AES_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    return decryptCipherText(cipher, cipherTextBytes);
  }

  private byte[] decryptCipherText(Cipher cipher, byte[] cipherTextBytes) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(cipherTextBytes);
    CipherInputStream cipherInputStream = new CipherInputStream(bais, cipher);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[256];
    int bytesRead = cipherInputStream.read(buffer);
    while (bytesRead != -1) {
      baos.write(buffer, 0, bytesRead);
      bytesRead = cipherInputStream.read(buffer);
    }
    return baos.toByteArray();
  }

  private SecretKey getSymmetricKey(String alias) throws GeneralSecurityException, IOException {
    byte[] cipherTextBytes = Storage.readValues(getContext(), Constants.SKS_KEY_FILENAME + alias);
    return new SecretKeySpec(decryptRsaCipherText(getPrivateKey(alias), cipherTextBytes), Constants.AES_ALGORITHM);
  }

  private String getPlainText(String alias) throws GeneralSecurityException, IOException {
    SecretKey secretKey = getSymmetricKey(alias);
    byte[] cipherTextBytes = Storage.readValues(getContext(), Constants.SKS_DATA_FILENAME + alias);
    return new String(decryptAesCipherText(secretKey, cipherTextBytes), "UTF-8");
  }

  @ReactMethod
  public void remove(String alias, Promise promise) {
    Storage.resetValues(getContext(), new String[] { 
      Constants.SKS_DATA_FILENAME + alias, 
      Constants.SKS_KEY_FILENAME + alias, 
    });
    promise.resolve("cleared alias");
  }

  private Context getContext() {
    return getReactApplicationContext();
  }

  private String getKeyStore() {
    try {
      KeyStore.getInstance(Constants.KEYSTORE_PROVIDER_1);
      return Constants.KEYSTORE_PROVIDER_1;
    } catch (Exception err) {
      try {
        KeyStore.getInstance(Constants.KEYSTORE_PROVIDER_2);
        return Constants.KEYSTORE_PROVIDER_2;
      } catch (Exception e) {
        return Constants.KEYSTORE_PROVIDER_3;
      }
    }
  }

}
