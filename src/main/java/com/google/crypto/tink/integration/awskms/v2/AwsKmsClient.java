/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.crypto.tink.integration.awskms.v2;

import com.google.common.base.Splitter;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.subtle.Validators;
import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkServiceException;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import javax.annotation.Nullable;

/**
 * AWS Key Management Service CLient that uses V2 of the AWS Java API.
 *
 * <p>Based heavily on
 * https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/integration/awskms/AwsKmsClient.java
 *
 */
public final class AwsKmsClient implements com.google.crypto.tink.KmsClient {
  /** The prefix of all keys stored in AWS KMS. */
  public static final String PREFIX = "aws-kms://";

  private static final String KMS_ENDPOINT_OVERRIDE = "KMS_ENDPOINT_OVERRIDE";
  @Nullable private KmsClient awsKmsClient;
  private AwsCredentialsProvider provider;
  private SdkHttpClient httpClient;
  private String keyUri;
  private URI kmsEndpointOverride;

  /**
   * Constructs a generic AwsKmsClient that is not bound to any specific key.
   *
   * This constructor should not be used. We recommend to register the client instead.
   */
  private AwsKmsClient() {}

  /**
   * Constructs a specific AwsKmsClient that is bound to a single key identified by {@code uri}.
   *
   * This constructor should not be used. We recommend to register the client instead.
   */
  private AwsKmsClient(String uri) {
    if (!uri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
  }

  /**
   * Specifies the {@link com.amazonaws.services.kms.AWSKMS} object to be used. Only used for
   * testing.
   */
  @CanIgnoreReturnValue
  com.google.crypto.tink.KmsClient withAwsKmsClient(@Nullable KmsClient awsKmsClient) {
    this.awsKmsClient = awsKmsClient;
    return this;
  }
  /**
   * @return true either if this client is a generic one and uri starts with {@link
   *     AwsKmsClient#PREFIX}, or the client is a specific one that is bound to the key identified
   *     by {@code uri}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (keyUri != null && keyUri.equals(uri)) {
      return true;
    }
    return keyUri == null && uri.toLowerCase(Locale.US).startsWith(PREFIX);
  }
  /**
   * Loads AWS credentials from an AWS profile file.
   *
   * <p>TODO: this is a breaking change.
   *
   * <p>The AWS access key ID is expected to be in the <code>accessKey</code> property and the AWS
   * secret key is expected to be in the <code>secretKey</code> property.
   *
   * @throws GeneralSecurityException if the client initialization fails
   */
  @Override
  public AwsKmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    Path path = FileSystems.getDefault().getPath(credentialPath);
    ProfileFile profileFile = ProfileFile.builder().content(path).build();
    ProfileCredentialsProvider provider =
            ProfileCredentialsProvider.builder().profileFile(profileFile).build();
    return withCredentialsProvider(provider);
  }

  /**
   * Loads default AWS credentials.
   *
   * <p>AWS credentials provider chain that looks for credentials in this order:
   *
   * <p>TODO: Verify this is the same default behavior.
   *
   * <ul>
   *   <li>Environment Variables - AWS_ACCESS_KEY_ID and AWS_SECRET_KEY
   *   <li>Java System Properties - aws.accessKeyId and aws.secretKey
   *   <li>Credential profiles file at the default location (~/.aws/credentials)
   *   <li>Instance profile credentials delivered through the Amazon EC2 metadata service
   * </ul>
   *
   * @throws GeneralSecurityException if the client initialization fails
   */
  @Override
  public AwsKmsClient withDefaultCredentials() throws GeneralSecurityException {
    try {
      return withCredentialsProvider(DefaultCredentialsProvider.create());
    } catch (SdkServiceException e) {
      throw new GeneralSecurityException("Cannot load default credentials", e);
    }
  }

  /** Loads AWS credentials from a provider. */
  public AwsKmsClient withCredentialsProvider(AwsCredentialsProvider provider)
          throws GeneralSecurityException {
    this.provider = provider;
    return this;
  }

  public AwsKmsClient withHttpClient(SdkHttpClient client) {
    this.httpClient = client;
    return this;
  }

  public AwsKmsClient withKmsEndpointOverride(URI endpoint) {
    this.kmsEndpointOverride = endpoint;
    return this;
  }

  private KmsClient createKmsClient(String region) {
    KmsClientBuilder builder =
            KmsClient.builder()
                    .credentialsProvider(provider)
                    .region(Region.of(region))
                    .httpClient(httpClient);

    // Override endpoint if present in system envs (Lambda run)
    // Note: at most one of these sources of the override will be non-null.
    Optional.ofNullable(System.getenv().get(KMS_ENDPOINT_OVERRIDE))
            .map(URI::create)
            .ifPresent(builder::endpointOverride);

    // Override endpoint if present in worker args (worker run).
    Optional.ofNullable(kmsEndpointOverride).ifPresent(builder::endpointOverride);
    return builder.build();
  }

  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
              String.format(
                      "This client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }

    String keyUri = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri);
    List<String> tokens = Splitter.on(':').splitToList(keyUri);
    KmsClient awsKmsClient = this.awsKmsClient;
    if (awsKmsClient == null) {
      awsKmsClient = createKmsClient(tokens.get(3));
    }

    try {
      return new AwsKmsAead(awsKmsClient, keyUri);
    } catch (SdkServiceException e) {
      throw new GeneralSecurityException("Cannot load credentials from provider", e);
    }
  }

  /**
   * Creates and registers a {@link #AwsKmsClient} with the Tink runtime.
   *
   * <p>If {@code keyUri} is present, it is the only key that the new client will support. Otherwise
   * the new client supports all AWS KMS keys.
   *
   * <p>If {@code credentialPath} is present, load the credentials from that. Otherwise use the
   * default credentials.
   *
   * <p>In many cases, it is not necessary to register the client. For example, you can create the
   * AwsKmsClient yourself and call {@link com.google.crypto.tink.integration.awskms.AwsKmsClient#getAead} to get a remote {@code Aead}. Use
   * this {@code Aead} to encrypt a keyset for with {@code
   * TinkProtoKeysetFormat.serializeEncryptedKeyset}, or to create an envelope {@code Aead} using
   * {@code KmsEnvelopeAead.create}.
   */
  public static void register(Optional<String> keyUri, Optional<String> credentialPath)
          throws GeneralSecurityException {
    registerWithAwsKmsClient(keyUri, credentialPath, null);
  }

  /**
   * Does the same as {@link #register}, but with an additional {@code awsKms} argument.
   */
  public static void registerWithAwsKmsClient(
          Optional<String> keyUri, Optional<String> credentialPath, @Nullable KmsClient awsKmsClient)
          throws GeneralSecurityException {
    com.google.crypto.tink.integration.awskms.v2.AwsKmsClient client;
    if (keyUri.isPresent()) {
      client = new com.google.crypto.tink.integration.awskms.v2.AwsKmsClient(keyUri.get());
    } else {
      client = new com.google.crypto.tink.integration.awskms.v2.AwsKmsClient();
    }
    if (credentialPath.isPresent()) {
      client.withCredentials(credentialPath.get());
    } else {
      client.withDefaultCredentials();
    }
    client.withAwsKmsClient(awsKmsClient);
    KmsClients.add(client);
  }
}